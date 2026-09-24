package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
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
	sizes := make([][2]int, 0, len(pages))
	for index, page := range pages {
		shown, width, height, err := pageForLocating(page, locateTargetPixels)
		if err != nil {
			log.Printf("document read-key: cannot prepare page %d to be shown: %v", index+1, err)
			return nil
		}
		images = append(images, inference.Image{MIMEType: "image/png", Data: shown})
		sizes = append(sizes, [2]int{width, height})
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
			// The size of the image the engine was shown, which is the only pixel space it can mean.
			x, y, width, height, inPixels := inFractions(placement.Box, sizes[placement.Page-1][0], sizes[placement.Page-1][1])
			if inPixels {
				log.Printf("document read-key: %s was answered in page pixels, not fractions; read as pixels", field)
			}
			box := redact.NormalisedBox(placement.Page, x, y, width, height, page.Width, page.Height)
			if box.Right-box.Left <= 0 || box.Bottom-box.Top <= 0 {
				log.Printf("document read-key: %s came back with an empty region", field)
				continue
			}
			// Grown only once it is known to be a region: growing nothing would put a box at a page
			// corner and show a part of the document nobody asked about.
			box = grow(box, boxMarginPoints, page.Width, page.Height)
			found[field] = box
		}
	}

	log.Printf("document read-key: the engine placed %d of %d value(s) on %d page(s) of a document with no text layer",
		len(found), len(fields), len(pages))
	return found
}

// locateTargetPixels is how many pixels a page may have when it is shown to the engine for locating.
//
// Measured against the real model, twice. Asked for fractions, it answers some values in pixels — and
// those pixels are the pixels of the image it was actually shown, never of the render we hold. Its
// encoder silently downscales anything above its own budget of roughly a million pixels (28x28 per
// token, about 1280 tokens), so a 200 DPI render was being scaled by about a half and a 1280-wide page
// by about two thirds: in both cases the boxes landed off the values and the page came back mostly
// blank paper. Showing a page within that budget is what makes the pixel space known. The render
// itself is still the full-resolution one — cutting and painting always use that.
const locateTargetPixels = 1_000_000

// pageForLocating returns the bytes to show, and the width and height the engine will therefore see.
func pageForLocating(page []byte, budget int) ([]byte, int, int, error) {
	source, _, err := image.Decode(bytes.NewReader(page))
	if err != nil {
		return nil, 0, 0, err
	}
	bounds := source.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if width*height <= budget {
		return page, width, height, nil
	}

	// Scaled by area, not by the long side: it is the encoder's pixel count that decides whether it
	// silently rescales the image behind our back and takes the pixel space away from us.
	scale := math.Sqrt(float64(budget) / float64(width*height))
	targetWidth := int(float64(width)*scale + 0.5)
	targetHeight := int(float64(height)*scale + 0.5)
	if targetWidth < 1 {
		targetWidth = 1
	}
	if targetHeight < 1 {
		targetHeight = 1
	}

	target := image.NewRGBA(image.Rect(0, 0, targetWidth, targetHeight))
	for y := 0; y < targetHeight; y++ {
		fromY := y * height / targetHeight
		toY := (y + 1) * height / targetHeight
		if toY <= fromY {
			toY = fromY + 1
		}
		for x := 0; x < targetWidth; x++ {
			fromX := x * width / targetWidth
			toX := (x + 1) * width / targetWidth
			if toX <= fromX {
				toX = fromX + 1
			}
			var red, green, blue, count uint32
			for sourceY := fromY; sourceY < toY && sourceY < height; sourceY++ {
				for sourceX := fromX; sourceX < toX && sourceX < width; sourceX++ {
					r, g, bl, _ := source.At(bounds.Min.X+sourceX, bounds.Min.Y+sourceY).RGBA()
					red += r >> 8
					green += g >> 8
					blue += bl >> 8
					count++
				}
			}
			if count == 0 {
				continue
			}
			target.Set(x, y, color.RGBA{uint8(red / count), uint8(green / count), uint8(blue / count), 255})
		}
	}

	var out bytes.Buffer
	if err := png.Encode(&out, target); err != nil {
		return nil, 0, 0, err
	}
	return out.Bytes(), targetWidth, targetHeight, nil
}

// inFractions reads an answer that may not be in the units it was asked for.
//
// A model asked for fractions of the page sometimes answers with a point in the render's pixels —
// and, measured against the real one, it does so per value rather than per answer: one field came
// back as [480, 395, 0.08, 0.02], the first two in pixels and the last two in fractions. Read as
// fractions, that box clamps to the page edge and comes out empty, which is how two scanned
// documents were withheld with nothing to show for it.
//
// So each number is read on its own: above 1 it cannot be a fraction of anything and is taken as
// pixels, which needs the render's own size to become a fraction. The second return says whether any
// value had to be read that way, because a model that keeps doing this should be visible in the log
// rather than silently tolerated.
func inFractions(box [4]float64, imageWidth, imageHeight int) (x, y, width, height float64, inPixels bool) {
	asFraction := func(value float64, extent int) float64 {
		if value <= 1.0 {
			return value
		}
		inPixels = true
		if extent <= 0 {
			return 1.0
		}
		return value / float64(extent)
	}
	return asFraction(box[0], imageWidth), asFraction(box[1], imageHeight), asFraction(box[2], imageWidth), asFraction(box[3], imageHeight), inPixels
}

// boxMarginPoints is how much a model's region is grown before anything is cut or painted from it.
//
// A model points at where a value is, and it is approximate: a box that stops a hair inside the
// value leaves half of it outside the piece, which is worse than showing a little more than asked.
// So every located region is grown by this much, clamped to the page.
const boxMarginPoints = 6.0

func grow(box redact.Box, margin, pageWidth, pageHeight float64) redact.Box {
	box.Left -= margin
	box.Top -= margin
	box.Right += margin
	box.Bottom += margin
	if box.Left < 0 {
		box.Left = 0
	}
	if box.Top < 0 {
		box.Top = 0
	}
	if box.Right > pageWidth {
		box.Right = pageWidth
	}
	if box.Bottom > pageHeight {
		box.Bottom = pageHeight
	}
	return box
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
