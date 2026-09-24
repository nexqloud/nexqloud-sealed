package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nexqloud-sealed/internal/documents"
	"nexqloud-sealed/internal/identity"
	"nexqloud-sealed/internal/inference"
	"nexqloud-sealed/internal/readkey"
	"nexqloud-sealed/internal/redact"
	"nexqloud-sealed/pkg/docwire"
)

// Where a value is printed is worked out when the document is read, sealed under the document's own
// key, and appended to the container the application keeps. These tests are about the two halves of
// that: the extraction locating what it read, and a review answering from what was located instead of
// asking the engine a second time.

// wordStub is the locator seam: a page's own words and where they are printed, without a document.
type wordStub struct {
	pages     []redact.Page
	err       error
	gotSource []byte
}

func (w *wordStub) Pages(_ context.Context, source []byte) ([]redact.Page, error) {
	w.gotSource = source
	if w.err != nil {
		return nil, w.err
	}
	return w.pages, nil
}

// countingInference counts the questions it is asked, which is how a test tells "the review reused
// what the extraction located" from "the review asked the engine all over again".
type countingInference struct {
	calls  int
	prompt string
	answer string
}

func (c *countingInference) Complete(req inference.Request) (inference.Response, error) {
	c.calls++
	c.prompt = req.Prompt
	return inference.Response{Content: c.answer, Model: "counting"}, nil
}

func (c *countingInference) CompleteStream(inference.Request, inference.TokenHandler) (inference.Response, error) {
	return inference.Response{}, nil
}

// wordsOfAPageThatPrintsBothValues is a 7501's two fields, on one page, where the form prints them.
func wordsOfAPageThatPrintsBothValues() []redact.Page {
	return []redact.Page{{
		Number: 1, Width: 612, Height: 792,
		Words: []redact.Word{
			{Text: "8207301500", Left: 100, Top: 200, Right: 200, Bottom: 212},
			{Text: "1200", Left: 100, Top: 300, Right: 140, Bottom: 312},
		},
	}}
}

// wordsOfAPageWithNoWords is a scan: a page with a size and nothing to find a value in.
func wordsOfAPageWithNoWords() []redact.Page {
	return []redact.Page{{Number: 1, Width: 612, Height: 792}}
}

func extractBodyAskingToLocate(fixture *sealedFixture) string {
	payload, _ := json.Marshal(map[string]any{
		"schema_id":       "cbp_7501",
		"schema":          json.RawMessage(extractSchema),
		"document_id":     fixture.documentID,
		"key_version":     fixture.keyVersion,
		"source_url":      "https://objects.example/case/source.nsdw?sig=abc",
		"challenge_nonce": testNonce(),
		"locate":          true,
	})
	return string(payload)
}

func TestTheExtractionLocatesTheValuesForTheReviewToReuse(t *testing.T) {
	srv, fixture, _, _ := extractServer(t)
	srv.words = &wordStub{pages: wordsOfAPageThatPrintsBothValues()}

	rec := httptest.NewRecorder()
	srv.handleDocumentExtract(rec, extractRequestWith(extractBodyAskingToLocate(fixture)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	var out extractResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not json: %v", err)
	}
	if out.Regions == nil {
		t.Fatal("a read that asked for the regions came back without any")
	}
	if out.Regions.LocatedFrom != readFromText {
		t.Fatalf("located_from = %q, want %q", out.Regions.LocatedFrom, readFromText)
	}
	if out.Regions.Fields != 2 || out.Regions.Asked != 2 {
		t.Fatalf("located %d of %d value(s)", out.Regions.Fields, out.Regions.Asked)
	}
	if out.Regions.Part.Name != docwire.RegionsName {
		t.Fatalf("the part is named %q, want %q", out.Regions.Part.Name, docwire.RegionsName)
	}

	sealed, err := base64.StdEncoding.DecodeString(out.Regions.BytesBase64)
	if err != nil {
		t.Fatalf("the sealed regions are not base64: %v", err)
	}
	// The part describes itself, and the description has to be the truth: the caller copies it into
	// the container's header without being able to check the bytes it covers.
	if out.Regions.Part.Bytes != len(sealed) || out.Regions.Part.SHA256 != docwire.Digest(sealed) {
		t.Fatalf("the part description does not cover the bytes handed over: %+v", out.Regions.Part)
	}

	// What the caller holds is sealed: the coordinates are not in it.
	if bytes.Contains(sealed, []byte("hts_10")) {
		t.Fatal("the located fields travel in the clear")
	}

	dek, keyVersion, err := srv.engine.DEK(identity.DevIdentity(""))
	if err != nil {
		t.Fatalf("DEK: %v", err)
	}
	kind, plaintext, err := documents.Open(dek, sealed, keyVersion)
	if err != nil {
		t.Fatalf("the sealed regions cannot be opened with the document's own key: %v", err)
	}
	if kind != documents.KindRegions {
		t.Fatalf("the regions part is a %s", kind)
	}
	var payload regionPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatalf("the regions payload is not readable: %v", err)
	}
	if payload.Version != regionsVersion || payload.LocatedFrom != readFromText {
		t.Fatalf("payload = %+v", payload)
	}
	for _, field := range []string{"hts_10", "qty"} {
		region, ok := payload.Fields[field]
		if !ok {
			t.Fatalf("%s was located but is not in the payload: %+v", field, payload.Fields)
		}
		if region.Page != 1 || region.Right <= region.Left || region.Bottom <= region.Top {
			t.Fatalf("%s was located at %+v", field, region)
		}
	}
}

func TestAReadThatDidNotAskForRegionsPaysForNone(t *testing.T) {
	srv, fixture, _, _ := extractServer(t)
	// A third value that could be placed nowhere, so a missing region is not what keeps this passing.
	words := &wordStub{pages: wordsOfAPageThatPrintsBothValues()}
	srv.words = words

	rec := httptest.NewRecorder()
	srv.handleDocumentExtract(rec, extractRequestWith(extractBody(fixture)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	var out extractResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not json: %v", err)
	}
	if out.Regions != nil {
		t.Fatalf("a read that asked for nothing extra was charged for it: %+v", out.Regions)
	}
	if words.gotSource != nil {
		t.Fatal("the page was read for words it was never asked about")
	}
}

// aPageAReviewCanBeShown is a real render, because a redaction paints black over a picture and there
// is nothing to paint over in a stub.
func aPageAReviewCanBeShown(t *testing.T) []byte {
	t.Helper()
	return pagePNG(t, 1224, 1584)
}

// sealedDocumentWithRegions is the container the application keeps after an extraction located the
// values: the ingest container, with the sealed regions part appended exactly as the caller does.
func sealedDocumentWithRegions(t *testing.T, srv *server, documentID string, keyVersion int, source []byte, pages [][]byte, found map[string]redact.Box) []byte {
	t.Helper()
	dek, version, err := srv.engine.DEK(identity.DevIdentity(""))
	if err != nil {
		t.Fatalf("DEK: %v", err)
	}
	sealed, err := sealRegions(dek, version, "cbp_7501", readFromText, found)
	if err != nil {
		t.Fatalf("sealRegions: %v", err)
	}
	var container bytes.Buffer
	if err := docwire.EncodeFull(&container, docwire.Header{
		DocumentID: documentID,
		KeyVersion: version,
	}, source, pages, docwire.Extras{Regions: sealed}); err != nil {
		t.Fatalf("encode container: %v", err)
	}
	return container.Bytes()
}

// reviewWithRegions wires a shim for the review path: one real page, a container that may carry the
// regions an extraction located, words for the page, and an engine that counts what it is asked.
func reviewWithRegions(t *testing.T, regions map[string]redact.Box, words *wordStub, answer string) (*server, *sealedFixture, *countingInference, *fakeFetcher) {
	t.Helper()
	srv := testHTTPServer(t)
	fixture := sealFixtureWithRender(t, srv, aPageAReviewCanBeShown(t))

	engine := &countingInference{answer: answer}
	srv.engine.Inference = engine
	srv.words = words

	stored := fixture.envelope
	if regions != nil {
		stored = sealedDocumentWithRegions(t, srv, fixture.documentID, fixture.keyVersion, fixture.envelope, fixture.pages, regions)
	} else {
		// A container written before there were regions anywhere: the ingest container, and nothing
		// else in it.
		var container bytes.Buffer
		if err := docwire.Encode(&container, docwire.Header{
			DocumentID: fixture.documentID,
			KeyVersion: fixture.keyVersion,
		}, fixture.envelope, fixture.pages); err != nil {
			t.Fatalf("encode container: %v", err)
		}
		stored = container.Bytes()
	}
	// Both shapes of stored bytes are fetched the same way: the container the application keeps.
	fetcher := &fakeFetcher{blob: stored}
	srv.fetcher = fetcher
	return srv, fixture, engine, fetcher
}

// sealFixtureWithRender seals a document whose page is a render a redaction can be painted on.
func sealFixtureWithRender(t *testing.T, srv *server, render []byte) *sealedFixture {
	t.Helper()
	dek, version, err := srv.engine.DEK(identity.DevIdentity(""))
	if err != nil {
		t.Fatalf("DEK: %v", err)
	}
	sealed, err := documents.SealDocument(dek, version, []byte(testPDF), [][]byte{render})
	if err != nil {
		t.Fatalf("SealDocument: %v", err)
	}
	return &sealedFixture{
		documentID: sealed.Fingerprint,
		keyVersion: sealed.KeyVersion,
		envelope:   sealed.Source,
		pages:      sealed.Pages,
	}
}

// theRegionOfTheBar is where the render's own grey bar is, in the page's points: the value a review
// is shown sits there, so a page that keeps it is a page with something on it.
func theRegionOfTheBar() redact.Box {
	return redact.Box{Page: 1, Left: 0, Top: 198, Right: 612, Bottom: 208}
}

func redactedPageOf(t *testing.T, srv *server, fixture *sealedFixture, reviewer *browser, fields map[string]any) (*httptest.ResponseRecorder, docwire.Header, docwire.Parts) {
	t.Helper()
	body := readKeyBody(fixture.documentID, reviewer, func(m map[string]any) {
		m["page"] = pageModeRedacted
		m["fields"] = fields
	})
	rec := httptest.NewRecorder()
	srv.handleDocumentReadKey(rec, readKeyHTTPRequest(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	header, parts, err := docwire.DecodeParts(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("the response is not a container: %v", err)
	}
	return rec, header, parts
}

func TestAReviewReusesTheRegionsTheExtractionKept(t *testing.T) {
	// Every value the review asks about was located when the document was read, so the engine is not
	// asked anything at all: that is the whole point of keeping the regions.
	words := &wordStub{pages: wordsOfAPageThatPrintsBothValues()}
	srv, fixture, engine, _ := reviewWithRegions(t, map[string]redact.Box{"hts_10": theRegionOfTheBar()}, words, "should not be asked")
	reviewer := newBrowser(t)

	_, header, parts := redactedPageOf(t, srv, fixture, reviewer, map[string]any{"hts_10": "8207301500"})
	if !header.Redacted {
		t.Fatal("the page handed over is not declared redacted")
	}
	if engine.calls != 0 {
		t.Fatalf("the engine was asked %d question(s) about a value that was already located", engine.calls)
	}
	if len(parts.Pages) != 1 {
		t.Fatalf("the grant carries %d page(s)", len(parts.Pages))
	}
	if len(parts.Pieces) != 1 || parts.Pieces[0].Name != "hts_10" {
		t.Fatalf("the pieces are %+v, want one for hts_10", parts.Pieces)
	}

	// And what the browser opens is the page with the region kept and the rest of it painted out.
	page := thePageTheBrowserOpens(t, reviewer, parts.Source, parts.Pages[0])
	img := decodePNG(t, page)
	if at(t, img, 100, 406) == (color.RGBA{0, 0, 0, 255}) {
		t.Fatal("the region the value is printed in was painted out")
	}
	if at(t, img, 100, 100) != (color.RGBA{0, 0, 0, 255}) {
		t.Fatal("a part of the page that is not under review was handed over")
	}
}

func TestAScanAsksTheEngineOnlyForWhatWasNotKept(t *testing.T) {
	// A scan has no words to find anything in, so the engine is the only thing that can place a value
	// on it — and it is asked about the one value the extraction did not already place, not about both.
	words := &wordStub{pages: wordsOfAPageWithNoWords()}
	placed := `{"qty": {"page": 1, "box": [0.4, 0.5, 0.1, 0.04]}}`
	srv, fixture, engine, _ := reviewWithRegions(t, map[string]redact.Box{"hts_10": theRegionOfTheBar()}, words, placed)
	reviewer := newBrowser(t)

	_, header, parts := redactedPageOf(t, srv, fixture, reviewer, map[string]any{
		"hts_10": "8207301500",
		"qty":    1200,
	})
	if !header.Redacted {
		t.Fatal("the page handed over is not declared redacted")
	}
	if engine.calls != 1 {
		t.Fatalf("the engine was asked %d question(s), want one for the value that was not already located", engine.calls)
	}
	if strings.Contains(engine.prompt, "hts_10") {
		t.Fatalf("the engine was asked about a value that was already located:\n%s", engine.prompt)
	}
	if !strings.Contains(engine.prompt, "- qty =") {
		t.Fatalf("the engine was not asked about the value that is missing a region:\n%s", engine.prompt)
	}
	if len(parts.Pieces) != 2 {
		t.Fatalf("the pieces are %+v, want one per located value", parts.Pieces)
	}
}

func TestAContainerWrittenBeforeTheRegionsIsLocatedForAsItAlwaysWas(t *testing.T) {
	// A container with no regions in it is what every case in the field holds today. It has to keep
	// working exactly as it did: the engine is asked about the values the words could not place.
	words := &wordStub{pages: wordsOfAPageWithNoWords()}
	placed := `{"qty": {"page": 1, "box": [0.4, 0.5, 0.1, 0.04]}, "hts_10": {"page": 1, "box": [0.1, 0.2, 0.3, 0.05]}}`
	srv, fixture, engine, _ := reviewWithRegions(t, nil, words, placed)
	reviewer := newBrowser(t)

	_, _, parts := redactedPageOf(t, srv, fixture, reviewer, map[string]any{
		"hts_10": "8207301500",
		"qty":    1200,
	})
	if engine.calls != 1 {
		t.Fatalf("the engine was asked %d question(s), want one for a document with no stored regions", engine.calls)
	}
	if !strings.Contains(engine.prompt, "- hts_10 =") || !strings.Contains(engine.prompt, "- qty =") {
		t.Fatalf("the engine was not asked about both values:\n%s", engine.prompt)
	}
	if len(parts.Pieces) != 2 {
		t.Fatalf("the pieces are %+v, want one per located value", parts.Pieces)
	}
}

// The container this side has to read is one the *application* wrote: it stores what an extraction
// handed it and this side fetches it back. `testdata/container-with-regions-from-the-app.b64` is that
// container, produced by the application's own writer — `build_container` plus `with_regions` in
// `backend/tests/test_document_api.py` of the tariff POC, with a one-page-per-render document and one
// sealed regions part — so a change to either side's idea of the format fails here rather than in a
// reviewer's browser.
func appWrittenContainer(t *testing.T) []byte {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join("testdata", "container-with-regions-from-the-app.b64"))
	if err != nil {
		t.Fatalf("the application's own container is missing: %v", err)
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatalf("the application's container is not base64: %v", err)
	}
	return blob
}

func TestTheContainerTheApplicationWritesIsReadAsItStands(t *testing.T) {
	header, parts, err := docwire.DecodeParts(bytes.NewReader(appWrittenContainer(t)))
	if err != nil {
		t.Fatalf("the container the application keeps cannot be read: %v", err)
	}
	if header.DocumentID != strings.Repeat("a", 64) || header.KeyVersion != 1 {
		t.Fatalf("header = %+v", header)
	}
	if !bytes.Equal(parts.Source, []byte("\xff\xd8 sealed source")) {
		t.Fatalf("source = %q", parts.Source)
	}
	// The pages are the pages, even with a part written after them by another language's writer.
	if len(parts.Pages) != 2 || !bytes.Equal(parts.Pages[0], []byte("page one")) || !bytes.Equal(parts.Pages[1], []byte("page two")) {
		t.Fatalf("pages = %q", parts.Pages)
	}
	if header.Regions == nil || header.Regions.Bytes != len(parts.Regions) {
		t.Fatalf("the header does not describe the regions that are there: %+v", header.Regions)
	}
	// And they arrive as one part of their own, sealed by the deployment: nothing here reads them.
	if !bytes.Equal(parts.Regions, []byte("\x7f\x00 an extraction's located regions, sealed inside the boundary")) {
		t.Fatalf("regions = %q", parts.Regions)
	}
	// The older reader must not hand a region back as a page either.
	_, _, rest, err := docwire.Decode(bytes.NewReader(appWrittenContainer(t)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	for i, blob := range rest {
		if bytes.Equal(blob, parts.Regions) {
			t.Fatalf("part %d is the regions, handed back as a page or a piece", i)
		}
	}
}

func TestTheNamesTheExtractionLocatesUnderAreTheNamesTheApplicationAsksUnder(t *testing.T) {
	// A region is asked for by name at review. The names are the application's — `lines.2.duty_paid_usd`,
	// a row numbered from one, counted the way the review screen counts — and the same rules decide what
	// is worth locating: an absent value is not a region, and a false flag is. The application's side of
	// this contract is `claim_fields.keep_set`, checked in `tests/test_claim_fields.py`; this is the
	// enclave's half of the same fixture.
	fields := map[string]any{
		"entry_number":       "231-4102887-9",
		"importer_of_record": nil,
		"lines": []any{
			map[string]any{
				"line_no":       1.0,
				"hts_10":        "7318150000",
				"qty":           2200.0,
				"duty_paid_usd": 12512.0,
				"add_cvd":       false,
				"note":          "",
			},
			map[string]any{"line_no": 2.0, "hts_10": "99030125", "qty": nil},
		},
	}

	named := valuesOnThePage(fields)

	if named["entry_number"] != "231-4102887-9" {
		t.Fatalf("a value printed on the page was not named: %+v", named)
	}
	if _, ok := named["importer_of_record"]; ok {
		t.Fatal("a value this read did not produce cannot be located")
	}
	for name, want := range map[string]any{
		"lines.1.line_no":       1.0,
		"lines.1.qty":           2200.0,
		"lines.1.duty_paid_usd": 12512.0,
		"lines.2.hts_10":        "99030125",
	} {
		if got := named[name]; got != want {
			t.Fatalf("%s = %v, want %v", name, got, want)
		}
	}
	// A false flag is a value the reviewer decides on, so it is worth locating; an empty string is not
	// a value at all, and a row that carries no quantity has no region to find.
	if got, ok := named["lines.1.add_cvd"]; !ok || got != false {
		t.Fatalf("the flag is %v (present: %v), want false", got, ok)
	}
	for _, absent := range []string{"lines.2.qty", "lines.1.note"} {
		if _, ok := named[absent]; ok {
			t.Fatalf("%s has no value to print, so it cannot have a region", absent)
		}
	}
}

func TestStoredRegionsAreRefusedWhenTheyAreNotRegions(t *testing.T) {
	// A container can carry something in the regions part that is not a set of regions at all: an
	// older payload, or bytes somebody else wrote. Nothing about it may reach a reviewer, and the
	// review falls back to locating for itself rather than showing a region nobody asked about.
	words := &wordStub{pages: wordsOfAPageWithNoWords()}
	srv := testHTTPServer(t)
	fixture := sealFixtureWithRender(t, srv, aPageAReviewCanBeShown(t))
	engine := &countingInference{answer: `{"hts_10": {"page": 1, "box": [0.1, 0.2, 0.3, 0.05]}}`}
	srv.engine.Inference = engine
	srv.words = words

	dek, version, err := srv.engine.DEK(identity.DevIdentity(""))
	if err != nil {
		t.Fatalf("DEK: %v", err)
	}
	notRegions, err := documents.Seal(dek, version, documents.KindRegions, []byte(`{"version": 99, "located_from": "text"}`))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	var container bytes.Buffer
	if err := docwire.EncodeFull(&container, docwire.Header{
		DocumentID: fixture.documentID,
		KeyVersion: fixture.keyVersion,
	}, fixture.envelope, fixture.pages, docwire.Extras{Regions: notRegions}); err != nil {
		t.Fatalf("encode container: %v", err)
	}
	srv.fetcher = &fakeFetcher{blob: container.Bytes()}

	reviewer := newBrowser(t)
	_, _, parts := redactedPageOf(t, srv, fixture, reviewer, map[string]any{"hts_10": "8207301500"})
	if engine.calls != 1 {
		t.Fatalf("the engine was asked %d question(s); a payload this reader does not know is not a region", engine.calls)
	}
	if len(parts.Pieces) != 1 {
		t.Fatalf("the pieces are %+v, want the one the engine placed", parts.Pieces)
	}
}

// thePageTheBrowserOpens unwraps the grant with the browser's own key and opens the page it was
// handed, which is the only way to see what a reviewer actually receives.
func thePageTheBrowserOpens(t *testing.T, reviewer *browser, grantJSON, sealedPage []byte) []byte {
	t.Helper()
	var grant readkey.Wrapped
	if err := json.Unmarshal(grantJSON, &grant); err != nil {
		t.Fatalf("the first part is not a grant: %v", err)
	}
	sessionKey, err := readkey.Open(reviewer.key, grant)
	if err != nil {
		t.Fatalf("the browser could not open its own grant: %v", err)
	}
	page, err := readkey.OpenPage(sessionKey, sealedPage)
	if err != nil {
		t.Fatalf("the browser could not open the page: %v", err)
	}
	return page
}

func decodePNG(t *testing.T, blob []byte) image.Image {
	t.Helper()
	img, _, err := image.Decode(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("decode page render: %v", err)
	}
	return img
}

func at(t *testing.T, img image.Image, x, y int) color.RGBA {
	t.Helper()
	if x >= img.Bounds().Dx() || y >= img.Bounds().Dy() {
		t.Fatalf("(%d,%d) is off a %v page", x, y, img.Bounds())
	}
	r, g, b, a := img.At(x, y).RGBA()
	return color.RGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8)}
}
