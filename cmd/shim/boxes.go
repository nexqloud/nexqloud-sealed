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

	temperature := 0.0
	maxTokens := maxBoxTokens
	completion, err := s.engine.Inference.Complete(inference.Request{
		Model:          strings.TrimSpace(model),
		Prompt:         boxPrompt(fields, len(pages)),
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
		log.Printf("document read-key: asking where the values are failed: %v", err)
		return nil
	}

	placements, err := parsePlacements(completion.Content)
	if err != nil {
		log.Printf("document read-key: the engine did not return usable regions: %v", err)
		return nil
	}

	found := map[string]redact.Box{}
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
	log.Printf("document read-key: the engine placed %d of %d value(s) on %d page(s) of a document with no text layer",
		len(found), len(fields), len(pages))
	return found
}

// maxBoxTokens bounds one locating answer: a handful of numbers per field, and nothing else.
const maxBoxTokens = 1024

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
func boxPrompt(fields map[string]any, pages int) string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)

	var out strings.Builder
	fmt.Fprintf(&out, "You are shown %d image(s), which are the pages of one document in order.\n\n", pages)
	out.WriteString("For each field below, say which region of which page its value is printed in.\n")
	out.WriteString("Answer as JSON only: {\"<field>\": {\"page\": <page number, 1 for the first image>, ")
	out.WriteString("\"box\": [x, y, width, height]}}, where the box is a fraction of that page's own width and ")
	out.WriteString("height (0 to 1) measured from its top left corner.\n\n")
	out.WriteString("Fields, with the value this document was read as holding:\n")
	for _, name := range names {
		fmt.Fprintf(&out, "- %s = %v\n", name, fields[name])
	}
	out.WriteString("\nLeave out any field whose value you cannot find in the images.")
	return out.String()
}

type placement struct {
	Page int        `json:"page"`
	Box  [4]float64 `json:"box"`
}

func parsePlacements(content string) (map[string]placement, error) {
	text := strings.TrimSpace(content)
	// The engine is constrained to this shape, but a fence or a stray sentence still happens.
	if start := strings.Index(text, "{"); start > 0 {
		text = text[start:]
	}
	if end := strings.LastIndex(text, "}"); end >= 0 && end < len(text)-1 {
		text = text[:end+1]
	}
	var placements map[string]placement
	if err := json.Unmarshal([]byte(text), &placements); err != nil {
		return nil, err
	}
	if len(placements) == 0 {
		return nil, fmt.Errorf("no regions in the answer")
	}
	return placements, nil
}
