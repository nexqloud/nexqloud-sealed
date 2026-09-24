package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"

	"nexqloud-sealed/internal/inference"
	"nexqloud-sealed/internal/redact"
)

// boxesFromModel asks the engine where each value is printed on a page it is shown.
//
// A page with no text layer has no other source of a location: what redact.Split reports are the
// words poppler reads, and a scan has none. But the read of such a document is already made from
// pictures, so the engine can answer where it saw a value as well as what it says — and that is the
// only thing that can turn a scan into a redacted page.
//
// The boxes are approximate by nature and are treated that way: redact.NormalisedBox puts them on
// the page, the caller grows them by a margin before painting, and a field the engine does not place
// is left out rather than guessed at. Showing slightly too much of a region is honest; showing the
// wrong one is not.
//
// The values are asked for in small batches, for two reasons learned from documents that came back
// with no page at all. An engine asked about a whole long form at once tends to answer with something
// that is not the shape it was asked for, and one unusable answer then costs every field on the
// document. In batches the answer is small enough to be relied on, and a batch that fails costs only
// its own fields — the rest of the page is still redacted and still reviewable.
func (s *server) boxesFromModel(ctx context.Context, fields map[string]any, pages [][]byte, dims []redact.Page, model, tenant, nonce string) map[string]redact.Box {
	if s.engine == nil || s.engine.Inference == nil {
		log.Printf("document read-key: no inference backend, so no region of a scan can be found")
		return nil
	}
	if len(fields) == 0 || len(pages) == 0 || len(pages) != len(dims) {
		return nil
	}

	images := make([]inference.Image, 0, len(pages))
	for _, page := range pages {
		images = append(images, inference.Image{MIMEType: "image/png", Data: page})
	}

	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)

	found := map[string]redact.Box{}
	for start := 0; start < len(names); start += maxBoxFields {
		end := start + maxBoxFields
		if end > len(names) {
			end = len(names)
		}
		batch := names[start:end]
		placements, err := s.askForBoxes(ctx, batch, fields, images, model, tenant, nonce)
		if err != nil {
			log.Printf("document read-key: no region for %s: %v", strings.Join(batch, ", "), err)
			continue
		}
		for field, placement := range placements {
			if placement.Page < 1 || placement.Page > len(dims) {
				log.Printf("document read-key: %s was placed on page %d, which is not in this document", field, placement.Page)
				continue
			}
			page := dims[placement.Page-1]
			if page.Width <= 0 || page.Height <= 0 {
				log.Printf("document read-key: page %d has no size, so a region on it cannot be placed", placement.Page)
				continue
			}
			box := redact.NormalisedBox(placement.Page, placement.Box[0], placement.Box[1], placement.Box[2], placement.Box[3], page.Width, page.Height)
			if box.Right-box.Left <= 0 || box.Bottom-box.Top <= 0 {
				log.Printf("document read-key: %s came back with an empty region", field)
				continue
			}
			found[field] = box
		}
	}

	log.Printf("document read-key: the engine placed %d of %d value(s) on %d page(s) of a document with no text layer",
		len(found), len(fields), len(pages))
	return found
}

// maxBoxFields is how many values one locating question carries. Small enough that the answer stays a
// shape an engine returns reliably; large enough that a long form is a handful of calls, not dozens.
const maxBoxFields = 8

// maxBoxTokens bounds one locating answer: a few numbers per field, and nothing else.
const maxBoxTokens = 2048

// askForBoxes puts one batch of values to the engine and reads its answer.
func (s *server) askForBoxes(ctx context.Context, batch []string, values map[string]any, images []inference.Image, model, tenant, nonce string) (map[string]placement, error) {
	temperature := 0.0
	maxTokens := maxBoxTokens
	completion, err := s.engine.Inference.Complete(inference.Request{
		Model:          strings.TrimSpace(model),
		Prompt:         boxPrompt(batch, values, len(images)),
		Images:         images,
		Temperature:    &temperature,
		MaxTokens:      &maxTokens,
		JSONSchema:     boxSchema,
		TenantID:       tenant,
		ChallengeNonce: nonce,
		// Locating a value on a picture is a question, not a deliberation.
		DisableThinking: true,
	})
	if err != nil {
		return nil, err
	}
	placements, err := parsePlacements(completion.Content)
	if err != nil {
		// What the engine actually said is the only way to fix a question that does not land, and this
		// side of the wire is where it can be seen. It is a location answer: no value is in it.
		log.Printf("document read-key: the engine's answer was not usable (%v); it said: %.300s", err, completion.Content)
		return nil, err
	}
	return placements, nil
}

const boxSchema = `{
  "type": "object",
  "additionalProperties": {
    "type": "object",
    "properties": {
      "page": {"type": "integer", "minimum": 1},
      "box": {"type": "array", "items": {"type": "number"}, "minItems": 4, "maxItems": 4}
    },
    "required": ["page", "box"],
    "additionalProperties": false
  }
}`

// boxPrompt names the pages and the values, and nothing about tariffs: what a value means is the
// caller's business, and this side only needs to know where it is printed.
func boxPrompt(batch []string, values map[string]any, pages int) string {
	var out strings.Builder
	fmt.Fprintf(&out, "You are shown %d image(s), which are the pages of one document in order.\n\n", pages)
	out.WriteString("For each field below, say which region of which page its value is printed in.\n")
	out.WriteString("Answer as JSON only: {\"<field>\": {\"page\": <page number, 1 for the first image>, ")
	out.WriteString("\"box\": [x, y, width, height]}}, where the box is a fraction of that page's own width and ")
	out.WriteString("height (0 to 1) measured from its top left corner.\n\n")
	out.WriteString("Fields, with the value this document was read as holding:\n")
	for _, name := range batch {
		fmt.Fprintf(&out, "- %s = %v\n", name, values[name])
	}
	out.WriteString("\nLeave out any field whose value you cannot find in the images.")
	return out.String()
}

type placement struct {
	Page int        `json:"page"`
	Box  [4]float64 `json:"box"`
}

// parsePlacements reads a locating answer, in the shapes an engine actually returns.
//
// The decoding constraint asks for one shape, and the lesson from a real deployment is that an engine
// still answers in others: the same map wrapped under a key of its own, or a list of entries naming
// their field. All three mean the same thing, and refusing two of them because the third was asked
// for loses a page for no reason.
func parsePlacements(content string) (map[string]placement, error) {
	text := strings.TrimSpace(content)
	if text == "" {
		return nil, fmt.Errorf("no answer")
	}

	// Keep whichever structure starts first: an object, or a list of entries.
	objectAt := strings.Index(text, "{")
	arrayAt := strings.Index(text, "[")
	switch {
	case arrayAt >= 0 && (objectAt < 0 || arrayAt < objectAt):
		text = text[arrayAt:]
		if end := strings.LastIndex(text, "]"); end >= 0 {
			text = text[:end+1]
		}
	default:
		if objectAt > 0 {
			text = text[objectAt:]
		}
		if end := strings.LastIndex(text, "}"); end >= 0 && end < len(text)-1 {
			text = text[:end+1]
		}
	}

	// A list of entries, each naming its field.
	if strings.HasPrefix(text, "[") {
		var rows []struct {
			Field string `json:"field"`
			placement
		}
		if err := json.Unmarshal([]byte(text), &rows); err != nil {
			return nil, err
		}
		out := make(map[string]placement, len(rows))
		for _, row := range rows {
			if row.Field != "" {
				out[row.Field] = row.placement
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("the answer was a list with no field named in it")
		}
		return out, nil
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, err
	}
	placements := make(map[string]placement, len(raw))
	nested := map[string]json.RawMessage{}
	for name, value := range raw {
		var one placement
		if err := json.Unmarshal(value, &one); err == nil && one.Page > 0 {
			placements[name] = one
			continue
		}
		// Not a placement: it may be an object of them, under a key of its own.
		var inner map[string]json.RawMessage
		if err := json.Unmarshal(value, &inner); err == nil {
			for innerName, innerValue := range inner {
				nested[innerName] = innerValue
			}
		}
	}
	for name, value := range nested {
		var one placement
		if err := json.Unmarshal(value, &one); err == nil && one.Page > 0 {
			placements[name] = one
		}
	}
	if len(placements) == 0 {
		return nil, fmt.Errorf("no regions in the answer")
	}
	return placements, nil
}
