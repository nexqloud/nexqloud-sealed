package render

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

// pagePNG builds a page whose every row is distinguishable, so a test can say which rows a band
// actually carries.
func pagePNG(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: uint8(y / 256), G: uint8(y % 256), B: uint8(x % 256), A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode test page: %v", err)
	}
	return buf.Bytes()
}

func decode(t *testing.T, pngBytes []byte) image.Image {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatalf("decode band: %v", err)
	}
	return img
}

func TestAPageInsideTheBudgetComesBackUntouched(t *testing.T) {
	// A page that needed nothing must not be re-encoded: the only thing a re-encode can do is
	// lose detail, and it would also change the digest the receipt covers.
	page := pagePNG(t, 100, 100)
	bands, err := SplitBands(page, 100*100)
	if err != nil {
		t.Fatalf("SplitBands: %v", err)
	}
	if len(bands) != 1 {
		t.Fatalf("got %d bands, want 1", len(bands))
	}
	if !bytes.Equal(bands[0].PNG, page) {
		t.Fatal("the band must be the page's own bytes")
	}
	if bands[0].Pixels != 100*100 {
		t.Fatalf("Pixels = %d, want %d", bands[0].Pixels, 100*100)
	}
}

func TestBandsTileThePageAndEachStaysInsideTheBudget(t *testing.T) {
	const (
		width, height = 200, 1000
		maxPixels     = 40_000 // band height 200, overlap 16, step 184
	)
	page := pagePNG(t, width, height)
	bands, err := SplitBands(page, maxPixels)
	if err != nil {
		t.Fatalf("SplitBands: %v", err)
	}
	if len(bands) < 2 {
		t.Fatalf("got %d bands, want the page cut up", len(bands))
	}

	var covered int
	for i, band := range bands {
		if band.Pixels > maxPixels {
			t.Fatalf("band %d carries %d pixels, over the %d budget", i, band.Pixels, maxPixels)
		}
		img := decode(t, band.PNG)
		if img.Bounds().Dx() != width {
			t.Fatalf("band %d is %d wide, want the page's %d", i, img.Bounds().Dx(), width)
		}
		if got := img.Bounds().Dy(); got != band.Pixels/width {
			t.Fatalf("band %d reports %d pixels but is %d rows", i, band.Pixels, got)
		}
		covered += img.Bounds().Dy()
	}

	// The first band starts at the page's first row and the last band ends at its last row: a read
	// that misses the bottom of the grid is how a duty amount goes missing.
	if !sameRow(t, bands[0].PNG, 0, page, 0) {
		t.Fatal("the first band does not start at the top of the page")
	}
	if !sameRow(t, bands[len(bands)-1].PNG, decode(t, bands[len(bands)-1].PNG).Bounds().Dy()-1, page, height-1) {
		t.Fatal("the last band does not reach the bottom of the page")
	}
	if covered <= height {
		t.Fatalf("bands cover %d rows with no overlap, want more than the page's %d", covered, height)
	}
}

func TestConsecutiveBandsOverlapSoABoundaryLineIsWhole(t *testing.T) {
	const (
		width, height = 200, 1000
		maxPixels     = 40_000 // band height 200, overlap 16, step 184
	)
	page := pagePNG(t, width, height)
	bands, err := SplitBands(page, maxPixels)
	if err != nil {
		t.Fatalf("SplitBands: %v", err)
	}
	// Band 0 covers rows 0..199 and band 1 starts at row 184, so a line straddling row 199 is whole
	// in one of them.
	if !sameRow(t, bands[1].PNG, 0, page, height-1000+184) {
		t.Fatal("the second band does not start at the overlapping row")
	}
	if !sameRow(t, bands[0].PNG, 199, page, 199) {
		t.Fatal("the first band does not reach the end of its own span")
	}
}

func TestTheLastBandIsNeverASliver(t *testing.T) {
	// 200 wide, so band height is 200 and the step 184: a page of 1200 rows would otherwise end
	// with 16 rows of pixels costing a whole image budget.
	page := pagePNG(t, 200, 1200)
	bands, err := SplitBands(page, 40_000)
	if err != nil {
		t.Fatalf("SplitBands: %v", err)
	}
	last := bands[len(bands)-1]
	rows := last.Pixels / 200
	if rows <= 16 {
		t.Fatalf("the last band is %d rows — a sliver", rows)
	}
}

func TestTokensFollowPixelsAndStopAtTheEncoderBudget(t *testing.T) {
	if got := (Band{Pixels: 1_017}).Tokens(); got != 1 {
		t.Fatalf("1017 pixels = %d tokens, want 1", got)
	}
	if got := (Band{Pixels: 1_017 * 2_000}).Tokens(); got != 2_000 {
		t.Fatalf("2000 tokens' worth of pixels = %d tokens", got)
	}
	if got := (Band{Pixels: 40_000_000}).Tokens(); got != MaxImageTokens {
		t.Fatalf("an over-sized band = %d tokens, want the encoder budget %d", got, MaxImageTokens)
	}
	if got := (Band{Pixels: 0}).Tokens(); got != 1 {
		t.Fatalf("an empty band = %d tokens, want at least 1", got)
	}
	if got := BandTokens([]Band{{Pixels: 1_017}, {Pixels: 1_017}}); got != 2 {
		t.Fatalf("BandTokens = %d, want 2", got)
	}
}

// sameRow compares one row of a band with one row of the page as decoded.
func sameRow(t *testing.T, bandPNG []byte, bandRow int, pagePNG []byte, pageRow int) bool {
	t.Helper()
	band, page := decode(t, bandPNG), decode(t, pagePNG)
	if bandRow < 0 || bandRow >= band.Bounds().Dy() || pageRow < 0 || pageRow >= page.Bounds().Dy() {
		return false
	}
	for x := 0; x < band.Bounds().Dx(); x++ {
		bandPixel := color.RGBAModel.Convert(band.At(band.Bounds().Min.X+x, band.Bounds().Min.Y+bandRow))
		pagePixel := color.RGBAModel.Convert(page.At(page.Bounds().Min.X+x, page.Bounds().Min.Y+pageRow))
		if bandPixel != pagePixel {
			return false
		}
	}
	return true
}
