package main

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"strings"
	"testing"

	"nexqloud-sealed/internal/chat"
	"nexqloud-sealed/internal/inference"
	"nexqloud-sealed/internal/redact"
)

// fakeEngine answers as the real engine is asked to: with a region per field.
type fakeEngine struct {
	answer string
	seen   inference.Request
}

func (f *fakeEngine) Complete(req inference.Request) (inference.Response, error) {
	f.seen = req
	return inference.Response{Content: f.answer, Model: "fake"}, nil
}
func (f *fakeEngine) CompleteStream(inference.Request, inference.TokenHandler) (inference.Response, error) {
	return inference.Response{}, nil
}

func pagePNG(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	draw.Draw(img, image.Rect(0, height/4, width, height/4+20), image.NewUniform(color.RGBA{200, 200, 200, 255}), image.Point{}, draw.Src)
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return out.Bytes()
}

// The whole point: a page with no words gets its regions from the engine that read it, and those
// regions land on the page in the page's own coordinates.
func TestAScanGetsItsRegionsFromTheEngine(t *testing.T) {
	engine := &fakeEngine{answer: `{"importer_of_record": {"page": 1, "box": [0.1, 0.2, 0.3, 0.05]},
		"lines.1.qty": {"page": 1, "box": [0.4, 0.5, 0.1, 0.04]}}`}
	server := &server{engine: &chat.Engine{Inference: engine}}

	pages := [][]byte{pagePNG(t, 1224, 1584)}
	dims := []redact.Page{{Number: 1, Width: 612, Height: 792}}

	found := server.boxesFromModel(context.Background(), map[string]any{
		"importer_of_record": "VANTAGE TOOL WORKS",
		"lines.1.qty":        1800.0,
	}, pages, dims, "qwen", "tenant", "nonce")

	if len(found) != 2 {
		t.Fatalf("both values were placed by the engine, got %d: %+v", len(found), found)
	}
	importer := found["importer_of_record"]
	// The page's own points, grown by the margin every located region gets before anything is cut.
	if math.Abs(importer.Left-(61.2-boxMarginPoints)) > 0.01 || math.Abs(importer.Top-(158.4-boxMarginPoints)) > 0.01 {
		t.Fatalf("the region has to be in the page's own points, got %+v", importer)
	}
	if importer.Page != 1 {
		t.Fatalf("the region has to say which page, got %+v", importer)
	}
	// And the image really was shown to the engine: a scan is located from a picture, not a guess.
	if len(engine.seen.Images) != 1 {
		t.Fatalf("the page has to be sent as an image, got %d", len(engine.seen.Images))
	}
	if !strings.Contains(engine.seen.Prompt, "importer_of_record = VANTAGE TOOL WORKS") {
		t.Fatalf("the prompt has to name the values it is asking about, got:\n%s", engine.seen.Prompt)
	}
	if !engine.seen.DisableThinking {
		t.Fatal("locating a value is a question, not a deliberation")
	}
}

func TestARegionOffThePageIsRefusedRatherThanPainted(t *testing.T) {
	engine := &fakeEngine{answer: `{"qty": {"page": 7, "box": [0.1, 0.1, 0.1, 0.1]},
		"hts_10": {"page": 1, "box": [0, 0, 0, 0]}}`}
	server := &server{engine: &chat.Engine{Inference: engine}}

	found := server.boxesFromModel(context.Background(), map[string]any{"qty": 1, "hts_10": "7318"},
		[][]byte{pagePNG(t, 1224, 1584)}, []redact.Page{{Number: 1, Width: 612, Height: 792}}, "qwen", "", "")

	if _, ok := found["qty"]; ok {
		t.Fatal("a page number that is not in the document must not become a region")
	}
	if _, ok := found["hts_10"]; ok {
		t.Fatal("an empty region must not become a region")
	}
}

func TestAnAnswerThatIsNotJSONPlacesNothing(t *testing.T) {
	engine := &fakeEngine{answer: "I could not read this document, sorry."}
	server := &server{engine: &chat.Engine{Inference: engine}}
	if found := server.boxesFromModel(context.Background(), map[string]any{"qty": 1},
		[][]byte{pagePNG(t, 1224, 1584)}, []redact.Page{{Number: 1, Width: 612, Height: 792}}, "qwen", "", ""); len(found) != 0 {
		t.Fatalf("an unusable answer places nothing, got %+v", found)
	}
}

func TestAnAnswerWrappedInProseIsStillRead(t *testing.T) {
	placements, err := parsePlacements("Here you go:\n```json\n{\"qty\": {\"page\": 1, \"box\": [0.4, 0.5, 0.1, 0.04]}}\n```\n")
	if err != nil {
		t.Fatalf("a fenced answer is still an answer: %v", err)
	}
	if placements["qty"].Page != 1 {
		t.Fatalf("want the placement read back, got %+v", placements)
	}
}

// An engine that wraps its answer in a key of its own still answered the question.
func TestAnAnswerWrappedInAKeyOfItsOwnIsStillRead(t *testing.T) {
	placements, err := parsePlacements(`{"regions": {"qty": {"page": 1, "box": [0.4, 0.5, 0.1, 0.04]}}}`)
	if err != nil {
		t.Fatalf("a wrapped answer is still an answer: %v", err)
	}
	if placements["qty"].Page != 1 {
		t.Fatalf("want the placement read back, got %+v", placements)
	}
}

// And so does an engine that answers with a list of entries.
func TestAnAnswerThatIsAListOfEntriesIsStillRead(t *testing.T) {
	placements, err := parsePlacements(`[{"field": "qty", "page": 2, "box": [0.1, 0.2, 0.3, 0.05]}]`)
	if err != nil {
		t.Fatalf("a list of entries is still an answer: %v", err)
	}
	if placements["qty"].Page != 2 {
		t.Fatalf("want the placement read back, got %+v", placements)
	}
}

// A long form is asked about in batches, so one unusable answer costs only its own fields.
func TestALongFormIsAskedAboutInBatches(t *testing.T) {
	engine := &fakeEngine{answer: `{"f1": {"page": 1, "box": [0.1, 0.1, 0.1, 0.1]}}`}
	counting := &countingEngine{inner: engine}
	server := &server{engine: &chat.Engine{Inference: counting}}

	fields := map[string]any{}
	for index := 0; index < maxBoxFields+3; index++ {
		fields[fmt.Sprintf("f%d", index)] = index
	}
	server.boxesFromModel(context.Background(), fields,
		[][]byte{pagePNG(t, 1224, 1584)}, []redact.Page{{Number: 1, Width: 612, Height: 792}}, "qwen", "", "")

	if counting.calls != 2 {
		t.Fatalf("%d fields in batches of %d is 2 questions, got %d", len(fields), maxBoxFields, counting.calls)
	}
}

type countingEngine struct {
	inner inference.Backend
	calls int
}

func (c *countingEngine) Complete(req inference.Request) (inference.Response, error) {
	c.calls++
	return c.inner.Complete(req)
}

// The pixel space an answer can be in is the one we sent, so the sent size is the one that counts.
func TestAPageShownToTheEngineIsMeasuredAsShown(t *testing.T) {
	_, width, height, err := pageForLocating(pagePNG(t, 2000, 1000), locateTargetPixels)
	if err != nil {
		t.Fatal(err)
	}
	if width*height > locateTargetPixels || width*height < locateTargetPixels*9/10 {
		t.Fatalf("a 2.0 megapixel page shown within a %d budget is %dx%d = %d", locateTargetPixels, width, height, width*height)
	}
	_, tallWidth, tallHeight, err := pageForLocating(pagePNG(t, 800, 1600), locateTargetPixels)
	if err != nil || tallWidth >= tallHeight {
		t.Fatalf("a portrait page stays portrait, got %dx%d (%v)", tallWidth, tallHeight, err)
	}
	if tallWidth*tallHeight > locateTargetPixels {
		t.Fatalf("a portrait page is still within the budget, got %d", tallWidth*tallHeight)
	}

	// A page already small enough is sent as it is: nothing is re-encoded for no reason.
	small := pagePNG(t, 800, 600)
	again, smallWidth, smallHeight, err := pageForLocating(small, locateTargetPixels)
	if err != nil || smallWidth != 800 || smallHeight != 600 {
		t.Fatalf("a small page keeps its size, got %d x %d (%v)", smallWidth, smallHeight, err)
	}
	if len(again) != len(small) {
		t.Fatalf("a small page is not re-encoded, got %d bytes from %d", len(again), len(small))
	}
}

// The measured failure: an engine answering in pixels for some values of the same box.
func TestAnAnswerInPixelsIsReadAsPixels(t *testing.T) {
	// Taken from the real answer for the bill of lading: x and y in the render's pixels, width and
	// height as fractions of it.
	x, y, width, height, inPixels := inFractions([4]float64{480, 395, 0.08, 0.02}, 1654, 2339)
	if !inPixels {
		t.Fatal("a value above 1 cannot be a fraction")
	}
	if math.Abs(x-480.0/1654) > 0.0001 || math.Abs(y-395.0/2339) > 0.0001 {
		t.Fatalf("pixels have to become fractions of the render: %v %v", x, y)
	}
	if width != 0.08 || height != 0.02 {
		t.Fatalf("values that are already fractions stay as they are: %v %v", width, height)
	}

	// And it lands on the page instead of collapsing onto its edge, which is what went wrong.
	box := redact.NormalisedBox(1, x, y, width, height, 595.44, 842.04)
	box = grow(box, boxMarginPoints, 595.44, 842.04)
	if box.Right-box.Left <= 0 || box.Bottom-box.Top <= 0 {
		t.Fatalf("the region has to be a region, got %+v", box)
	}
	if box.Right > 595.44 || box.Bottom > 842.04 || box.Left < 0 || box.Top < 0 {
		t.Fatalf("growing a region must not push it off the page, got %+v", box)
	}
}

func TestAnAnswerInFractionsSaysSo(t *testing.T) {
	x, y, _, _, inPixels := inFractions([4]float64{0.4, 0.5, 0.1, 0.04}, 1224, 1584)
	if inPixels {
		t.Fatal("fractions are not pixels")
	}
	if x != 0.4 || y != 0.5 {
		t.Fatalf("fractions pass through unchanged, got %v %v", x, y)
	}
}

func TestNoEngineMeansNoRegion(t *testing.T) {
	server := &server{}
	if found := server.boxesFromModel(context.Background(), map[string]any{"qty": 1},
		[][]byte{pagePNG(t, 1224, 1584)}, []redact.Page{{Number: 1, Width: 612, Height: 792}}, "qwen", "", ""); found != nil {
		t.Fatalf("without an engine nothing can be located, got %+v", found)
	}
}
