package redact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestNeedlesReadAStoredNumberAsTheFormPrintsIt(t *testing.T) {
	found := Needles(12512.0)
	if len(found) == 0 {
		t.Fatal("a stored number has to be looked for somehow")
	}
	var whole, money bool
	for _, needle := range found {
		switch needle.Text {
		case "12512":
			whole = true
		case "1251200":
			money = true
		}
		if !needle.Numeric {
			t.Errorf("needle %q should be numeric", needle.Text)
		}
	}
	if !whole || !money {
		t.Fatalf("want both 12512 and 1251200, got %+v", found)
	}
}

func TestMatchRefusesANumberInsideALongerNumber(t *testing.T) {
	page := Page{Number: 1, Width: 612, Height: 792, Words: []Word{
		{Text: "112512", Left: 10, Top: 10, Right: 40, Bottom: 20},
		{Text: "12,512", Left: 10, Top: 40, Right: 40, Bottom: 50},
	}}
	box, ok := Match(page, map[string]any{"duty": 12512.0})["duty"]
	if !ok {
		t.Fatal("the value is printed on this page and has to be found")
	}
	if math.Abs(box.Top-40) > 0.01 {
		t.Fatalf("matched the wrong region: %+v", box)
	}
}

func TestMatchSpansWordsAndMissesWhatIsNotThere(t *testing.T) {
	page := Page{Number: 2, Width: 612, Height: 792, Words: []Word{
		{Text: "29.", Left: 20, Top: 80, Right: 32, Bottom: 90},
		{Text: "THE", Left: 40, Top: 80, Right: 60, Bottom: 90},
		{Text: "HARDWARE", Left: 64, Top: 80, Right: 110, Bottom: 90},
		{Text: "DEPOT,", Left: 114, Top: 80, Right: 150, Bottom: 90},
		{Text: "INC.", Left: 154, Top: 80, Right: 180, Bottom: 90},
	}}
	found := Match(page, map[string]any{
		"importer_of_record": "THE HARDWARE DEPOT",
		"nowhere":            "VANTAGE TOOL WORKS",
	})
	box, ok := found["importer_of_record"]
	if !ok {
		t.Fatal("a value spread over several words still has one region")
	}
	if box.Left != 40 || box.Right != 150 {
		t.Fatalf("the box should cover the words the value is printed in, got %+v", box)
	}
	if box.Page != 2 {
		t.Fatalf("the box has to say which page it is on, got %+v", box)
	}
	if _, ok := found["nowhere"]; ok {
		t.Fatal("a value that is not on the page must not come back with a region")
	}
}

func TestAMultiLineValueKeepsEveryLineItIsPrintedOn(t *testing.T) {
	page := Page{Number: 1, Width: 612, Height: 792, Words: []Word{
		{Text: "THE", Left: 20, Top: 60, Right: 40, Bottom: 70},
		{Text: "HARDWARE", Left: 44, Top: 60, Right: 90, Bottom: 70},
		{Text: "DEPOT,", Left: 94, Top: 60, Right: 124, Bottom: 70},
		{Text: "INC.", Left: 128, Top: 60, Right: 150, Bottom: 70},
		{Text: "88", Left: 20, Top: 72, Right: 32, Bottom: 82},
		{Text: "CANAL", Left: 36, Top: 72, Right: 68, Bottom: 82},
		{Text: "STREET", Left: 72, Top: 72, Right: 108, Bottom: 82},
		{Text: "CHICAGO,", Left: 20, Top: 84, Right: 66, Bottom: 94},
		{Text: "IL", Left: 70, Top: 84, Right: 80, Bottom: 94},
		{Text: "60606", Left: 84, Top: 84, Right: 112, Bottom: 94},
	}}
	stored := "THE HARDWARE DEPOT, INC.\n88 CANAL STREET\nCHICAGO, IL 60606"
	box, ok := Match(page, map[string]any{"importer_of_record": stored})["importer_of_record"]
	if !ok {
		t.Fatal("the importer is printed on this page and has to be found")
	}
	if box.Top != 60 || box.Bottom != 94 {
		t.Fatalf("the region should cover every line the value is printed on, got %+v", box)
	}
}

func TestNeedlesRefuseAValueTooShortToLookFor(t *testing.T) {
	if got := Needles(5); len(got) != 0 {
		t.Fatalf("a single digit would match half the page, got %+v", got)
	}
	if got := Needles("AB"); len(got) != 0 {
		t.Fatalf("two letters would match inside another word, got %+v", got)
	}
	if got := Needles("AIR"); len(got) != 1 || got[0].Text != "air" {
		t.Fatalf("three letters are findable, got %+v", got)
	}
}

func TestNeedlesLookForADateTheWayTheFormPrintsIt(t *testing.T) {
	var us bool
	for _, needle := range Needles("2025-03-14") {
		if needle.Text == "03142025" {
			us = true
		}
	}
	if !us {
		t.Fatal("an ISO date has to be looked for as the form's own MM/DD/YYYY as well")
	}
}

func TestLocateSaysWhatItCouldNotFind(t *testing.T) {
	page := Page{Number: 1, Width: 612, Height: 792, Words: []Word{
		{Text: "VANTAGE", Left: 10, Top: 10, Right: 60, Bottom: 20},
	}}
	found, missing := Locate([]Page{page}, map[string]any{
		"importer": "VANTAGE",
		"duty":     12512.0,
	})
	if _, ok := found["importer"]; !ok {
		t.Fatal("the value on the page has to be found")
	}
	if _, ok := missing["duty"]; !ok {
		t.Fatal("a value that is not on the page has to be reported, not dropped")
	}
}

// The synthetic page is 612x792 points drawn at twice that in pixels, with one line under review
// and one line that is none of the reviewer's business.
const (
	testPageWidthPt  = 612.0
	testPageHeightPt = 792.0
	testPageScale    = 2
	testKeptLine     = 110.0 // points, inside testKeep
	testOtherLine    = 400.0 // points, well outside it
)

// testKeep is the one region that may be shown: the reviewer's business, and nothing else.
var testKeep = Box{Page: 1, Left: 20, Top: 100, Right: 200, Bottom: 120}

// grey is what the synthetic page draws its lines in, so a kept pixel is neither white (untouched)
// nor black (painted out): it is the page's own content, still there.
const grey = 128

func syntheticReviewPage(t *testing.T) []byte {
	t.Helper()
	return syntheticPage(t, []image.Rectangle{
		image.Rect(40, int(testKeptLine), 400, int(testKeptLine)+20),
		image.Rect(40, int(testOtherLine), 400, int(testOtherLine)+20),
	})
}

// The kept line sits at pixel y 220..260 and the other at 800..840, so a pixel at y=240 has to
// survive and a pixel at y=810 must not.
const (
	keptPixelX, keptPixelY   = 200, 240
	otherPixelX, otherPixelY = 200, 810
)

func TestBlackKeepsTheRegionsItWasGivenAndPaintsOutTheRest(t *testing.T) {
	blob, err := Black(syntheticReviewPage(t), testPageWidthPt, []Box{testKeep})
	if err != nil {
		t.Fatalf("Black: %v", err)
	}
	img := decodePNG(t, blob)

	if got := pixel(t, img, keptPixelX, keptPixelY); got.R != grey {
		t.Fatalf("the region under review has to keep the page's own pixels, got %v", got)
	}
	if got := pixel(t, img, otherPixelX, otherPixelY); got.R > 40 || got.G > 40 || got.B > 40 {
		t.Fatalf("everything else has to be painted out, pixel is %v", got)
	}
}

func TestBlackPaintsOutAPageWithNothingKept(t *testing.T) {
	blob, err := Black(syntheticReviewPage(t), testPageWidthPt, nil)
	if err != nil {
		t.Fatalf("Black: %v", err)
	}
	img := decodePNG(t, blob)
	if got := pixel(t, img, keptPixelX, keptPixelY); got.R > 40 {
		t.Fatalf("a page with nothing to keep is entirely painted out, pixel is %v", got)
	}
}

func TestCropCutsTheRegionItWasGiven(t *testing.T) {
	blob, err := Crop(syntheticReviewPage(t), testPageWidthPt, testKeep)
	if err != nil {
		t.Fatalf("Crop: %v", err)
	}
	img := decodePNG(t, blob)
	if img.Bounds().Dx() > 500 || img.Bounds().Dy() > 500 {
		t.Fatalf("a piece is a piece, not a page: %v", img.Bounds())
	}
	// The kept line starts 12pt inside the crop's own top edge, at twice that in pixels.
	if got := pixel(t, img, 100, 44); got.R != grey {
		t.Fatalf("the piece has to hold the region, pixel is %v", got)
	}
}

// TestSplitReadsWhatThePagePrintsAndWhere is the orientation check: a line drawn high on the page
// comes back with a small y, because poppler measures from the top. (The application's own first
// attempt cut a crop a quarter of a page too high by assuming the opposite.)
func TestSplitReadsWhatThePagePrintsAndWhere(t *testing.T) {
	if _, err := exec.LookPath("pdftotext"); err != nil {
		t.Skip("poppler is not installed here")
	}
	pages, err := Split(context.Background(), minimalPDF("THE HARDWARE DEPOT, INC."))
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(pages) != 1 {
		t.Fatalf("want one page, got %d", len(pages))
	}
	page := pages[0]
	if page.Width < 600 || page.Height < 780 {
		t.Fatalf("page size looks wrong: %v x %v", page.Width, page.Height)
	}
	found := Match(page, map[string]any{"importer_of_record": "THE HARDWARE DEPOT"})
	box, ok := found["importer_of_record"]
	if !ok {
		t.Fatalf("the text is on the page and has to be found; words were %+v", page.Words)
	}
	if box.Top > 200 {
		t.Fatalf("a line at the top of the page must not report a large y: %+v", box)
	}
	if box.Right <= box.Left {
		t.Fatalf("a box has to have width: %+v", box)
	}
}

// minimalPDF is one page with one line of text, near the top, so this package can be tested without
// shipping a document.
func minimalPDF(line string) []byte {
	content := fmt.Sprintf("BT /F1 12 Tf 72 700 Td (%s) Tj ET", line)
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] " +
			"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}

	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects)+1)
	for index, body := range objects {
		offsets[index+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", index+1, body)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return out.Bytes()
}

// syntheticPage draws dark lines on white at the given positions, in points.
func syntheticPage(t *testing.T, bars []image.Rectangle) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, int(testPageWidthPt)*testPageScale, int(testPageHeightPt)*testPageScale))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	for _, bar := range bars {
		draw.Draw(img, image.Rect(
			bar.Min.X*testPageScale, bar.Min.Y*testPageScale,
			bar.Max.X*testPageScale, bar.Max.Y*testPageScale,
		), image.NewUniform(color.RGBA{R: grey, G: grey, B: grey, A: 255}), image.Point{}, draw.Src)
	}
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		t.Fatalf("encode synthetic page: %v", err)
	}
	return out.Bytes()
}

func decodePNG(t *testing.T, blob []byte) image.Image {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("decode png: %v", err)
	}
	return img
}

func pixel(t *testing.T, img image.Image, x, y int) color.RGBA {
	t.Helper()
	r, g, b, a := img.At(x, y).RGBA()
	return color.RGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8)}
}

// TestAgainstARealDocument is the by-eye check, and it is opt-in because it needs a document and a
// renderer: REDACT_SOURCE names a PDF, REDACT_VALUES a JSON object of field to value, REDACT_OUT a
// directory to write what a reviewer would actually be handed into. Poppler draws the pages, exactly
// as the shim does.
//
//	REDACT_SOURCE=... REDACT_VALUES=... REDACT_OUT=... go test ./internal/redact -run RealDocument -v
func TestAgainstARealDocument(t *testing.T) {
	source, values, out := os.Getenv("REDACT_SOURCE"), os.Getenv("REDACT_VALUES"), os.Getenv("REDACT_OUT")
	if source == "" || values == "" || out == "" {
		t.Skip("set REDACT_SOURCE, REDACT_VALUES and REDACT_OUT to check a real document")
	}
	for _, tool := range []string{"pdftotext", "pdftoppm"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed here", tool)
		}
	}

	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	body, err := os.ReadFile(values)
	if err != nil {
		t.Fatalf("read values: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatalf("parse values: %v", err)
	}

	pages, err := Split(context.Background(), raw)
	if errors.Is(err, ErrNoText) {
		// The honest outcome for a scan, and the reason the caller is told no pages rather than
		// handed an unredacted one.
		t.Skipf("nothing to locate in this document: %v", err)
	}
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	found, missing := Locate(pages, fields)
	t.Logf("%d page(s); located %d of %d value(s)", len(pages), len(found), len(fields))
	for field := range missing {
		t.Logf("  no region for %s", field)
	}

	keeps := map[int][]Box{}
	for _, box := range found {
		keeps[box.Page] = append(keeps[box.Page], box)
	}

	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatalf("output dir: %v", err)
	}
	for index := range pages {
		number := index + 1
		pngBytes, err := renderPage(t, source, number)
		if err != nil {
			t.Fatalf("render page %d: %v", number, err)
		}
		blob, err := Black(pngBytes, pages[index].Width, keeps[number])
		if err != nil {
			t.Fatalf("Black page %d: %v", number, err)
		}
		writeOut(t, filepath.Join(out, fmt.Sprintf("redacted-%d.png", number)), blob)

		// And a piece per value that was found on this page.
		for field, box := range found {
			if box.Page != number {
				continue
			}
			piece, err := Crop(pngBytes, pages[index].Width, box)
			if err != nil {
				t.Errorf("Crop %s: %v", field, err)
				continue
			}
			writeOut(t, filepath.Join(out, "piece-"+strings.ReplaceAll(field, "/", "_")+".png"), piece)
		}
	}
}

func renderPage(t *testing.T, source string, number int) ([]byte, error) {
	t.Helper()
	dir := t.TempDir()
	prefix := filepath.Join(dir, "page")
	_, err := exec.Command("pdftoppm", "-png", "-r", "200", "-f", strconv.Itoa(number), "-l", strconv.Itoa(number), source, prefix).CombinedOutput()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".png") {
			return os.ReadFile(filepath.Join(dir, entry.Name()))
		}
	}
	return nil, fmt.Errorf("poppler drew nothing for page %d", number)
}

func writeOut(t *testing.T, path string, blob []byte) {
	t.Helper()
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	t.Logf("wrote %s (%d bytes)", path, len(blob))
}

func TestCoreStripsWhatIsNotLettersOrDigits(t *testing.T) {
	if got := core("$12,512.00"); !strings.Contains(got, "12512") {
		t.Fatalf("core(%q) = %q", "$12,512.00", got)
	}
}
