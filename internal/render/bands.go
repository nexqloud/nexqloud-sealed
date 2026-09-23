package render

import (
	"bytes"
	"fmt"
	"image"
	"image/draw"
	"image/png"
)

// What a vision encoder does with a page, measured against the served model rather than assumed:
//
//	200 DPI  1700x2200 ( 3.7 Mpx)  ->  3676 prompt tokens
//	400 DPI  3400x4400 (15.0 Mpx)  ->  4051 prompt tokens
//	600 DPI  5100x6600 (33.7 Mpx)  ->  4051 prompt tokens   (the cap)
//
// So an image is resized to a fixed budget near 4,000 tokens, and below that budget the model
// spends roughly one token per 1,000 page pixels. Two consequences decide this file:
//
//   - Rendering a whole page finer than about 200 DPI is wasted: a 400 DPI page is downscaled back
//     to the same budget, so the small print on it is no more readable than before.
//   - The budget is *per image*. A page cut into strips, each inside the budget, keeps the fine
//     print at the resolution it was rendered at, because every strip gets its own 4,000 tokens
//     instead of sharing one budget with the whole page.
//
// Which is what SplitBands is for: it is how the enclosure spends its context on the region that
// carries the values, without deciding in advance which region that is.
const (
	// PixelsPerToken is how much page the model reads per token, under its per-image budget.
	PixelsPerToken = 1017
	// MaxImageTokens is the per-image budget the encoder resizes to, whatever it is given.
	MaxImageTokens = 4051
	// MaxImagePixels is that budget in pixels — the most a single image should carry, since
	// anything above it is thrown away by a downscale that also blurs what it keeps.
	MaxImagePixels = 4_000_000
)

// Band is one horizontal strip of a rendered page, with the pixel count its cost follows from.
type Band struct {
	// PNG is the strip, encoded and ready to attach. For a page that needs no cutting it is the
	// page's own bytes, unchanged.
	PNG []byte
	// Pixels is width x height of the strip, which is what its share of the context follows from.
	Pixels int
}

// Tokens is what this band costs the model: its pixels over the measured ratio, never above the
// encoder's per-image budget.
func (b Band) Tokens() int {
	tokens := b.Pixels / PixelsPerToken
	if tokens > MaxImageTokens {
		return MaxImageTokens
	}
	if tokens < 1 {
		return 1
	}
	return tokens
}

// SplitBands cuts a rendered page into horizontal strips of at most maxPixels each.
//
// The strips tile the page top to bottom with a small overlap, so a value that sits on a boundary
// is whole in one of them — a cut through the middle of a quantity is how a read turns a number
// into a guess. A page already inside the budget comes back as it is: one band, its own bytes, no
// re-encode, because re-encoding a page that needed nothing could only lose detail.
func SplitBands(page []byte, maxPixels int) ([]Band, error) {
	decoded, err := png.Decode(bytes.NewReader(page))
	if err != nil {
		return nil, fmt.Errorf("render: decode page for banding: %w", err)
	}
	bounds := decoded.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("render: page has no pixels (%dx%d)", width, height)
	}
	if maxPixels <= 0 {
		maxPixels = MaxImagePixels
	}
	if width*height <= maxPixels {
		return []Band{{PNG: page, Pixels: width * height}}, nil
	}

	bandHeight := maxPixels / width
	if bandHeight < 1 {
		bandHeight = 1
	}
	if bandHeight >= height {
		return []Band{{PNG: page, Pixels: width * height}}, nil
	}
	// A twelfth of a band of overlap: enough to keep a line of print whole across a boundary,
	// small enough not to change the cost of the read.
	overlap := bandHeight / 12
	step := bandHeight - overlap
	if step < 1 {
		step = 1
	}

	bands := make([]Band, 0, height/step+1)
	for top := 0; top < height; top += step {
		bottom := top + bandHeight
		if bottom > height {
			bottom = height
		}
		// Never leave a sliver: a last strip shorter than the overlap would cost a whole image
		// budget for a few rows of pixels.
		if height-bottom > 0 && height-bottom <= overlap {
			bottom = height
		}
		strip := image.NewRGBA(image.Rect(0, 0, width, bottom-top))
		draw.Draw(strip, strip.Bounds(), decoded, image.Point{X: bounds.Min.X, Y: bounds.Min.Y + top}, draw.Src)
		var encoded bytes.Buffer
		encoder := png.Encoder{CompressionLevel: png.BestSpeed}
		if err := encoder.Encode(&encoded, strip); err != nil {
			return nil, fmt.Errorf("render: encode band: %w", err)
		}
		bands = append(bands, Band{PNG: encoded.Bytes(), Pixels: width * (bottom - top)})
		if bottom == height {
			break
		}
	}
	return bands, nil
}

// BandTokens is what a set of bands costs the model, which is what a read has to fit in the
// engine's context.
func BandTokens(bands []Band) int {
	total := 0
	for _, band := range bands {
		total += band.Tokens()
	}
	return total
}
