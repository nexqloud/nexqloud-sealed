package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nexqloud-sealed/internal/documents"
	"nexqloud-sealed/internal/identity"
	"nexqloud-sealed/internal/inference"
	"nexqloud-sealed/internal/keyscope"
	"nexqloud-sealed/internal/receipt"
	"nexqloud-sealed/internal/render"
)

const extractSchema = `{
  "type": "object",
  "properties": {
    "hts_10": {"type": ["string", "null"]},
    "qty":    {"type": ["number", "null"]}
  }
}`

const extractDocumentText = "CBP 7501 ENTRY SUMMARY\nHTS 10 8207301500\nQuantity 1200 PCS\n"

const extractAnswer = `{"fields":{"hts_10":"8207301500","qty":1200}}`

type fakeFetcher struct {
	blob []byte
	err  error
	url  string
}

func (f *fakeFetcher) Fetch(_ context.Context, url string) ([]byte, error) {
	f.url = url
	return f.blob, f.err
}

type stubInference struct {
	content  string
	logprobs []inference.TokenLogprob
	err      error
	req      inference.Request
}

func (s *stubInference) Complete(req inference.Request) (inference.Response, error) {
	s.req = req
	if s.err != nil {
		return inference.Response{}, s.err
	}
	return inference.Response{Content: s.content, Model: "sealed-test-model", TokenLogprobs: s.logprobs}, nil
}

// extractServer wires a shim for the extraction path: a sealed document in memory,
// a text extractor, and a model that answers with a fixed record.
func extractServer(t *testing.T) (*server, *sealedFixture, *fakeFetcher, *stubInference) {
	t.Helper()
	srv := testHTTPServer(t)

	fixture := sealFixture(t, srv)
	fetcher := &fakeFetcher{blob: fixture.envelope}
	model := &stubInference{content: extractAnswer, logprobs: answerTokens()}

	srv.fetcher = fetcher
	srv.text = &textStub{}
	srv.engine.Inference = model
	return srv, fixture, fetcher, model
}

type sealedFixture struct {
	documentID string
	keyVersion int
	envelope   []byte
	pages      [][]byte
}

func sealFixture(t *testing.T, srv *server) *sealedFixture {
	t.Helper()
	id := identity.DevIdentity("")
	dek, version, err := srv.engine.DEK(id)
	if err != nil {
		t.Fatalf("DEK: %v", err)
	}
	sealed, err := documents.SealDocument(dek, version, []byte(testPDF), [][]byte{pngPage("page 1")})
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

// textStub is the text extractor seam, kept as a tiny type so the fixture above
// reads cleanly.
type textStub struct {
	text   string
	err    error
	gotPDF []byte
}

func (s *textStub) Text(_ context.Context, pdf []byte, _ render.TextOptions) (string, error) {
	s.gotPDF = pdf
	if s.err != nil {
		return "", s.err
	}
	if s.text == "" {
		return extractDocumentText, nil
	}
	return s.text, nil
}

// answerTokens is the token stream for extractAnswer, with the HTS code written
// with little confidence and the quantity with a lot.
func answerTokens() []inference.TokenLogprob {
	return []inference.TokenLogprob{
		{Token: `{"fields":{`, Logprob: -0.01},
		{Token: `"hts_10"`, Logprob: -0.01},
		{Token: `:"`, Logprob: -0.01},
		{Token: `8207301500`, Logprob: -2.0},
		{Token: `",`, Logprob: -0.01},
		{Token: `"qty"`, Logprob: -0.01},
		{Token: `:1200`, Logprob: -0.05},
		{Token: `}}`, Logprob: -0.01},
	}
}

func extractBody(fixture *sealedFixture) string {
	payload, _ := json.Marshal(map[string]any{
		"schema_id":       "cbp_7501",
		"schema":          json.RawMessage(extractSchema),
		"document_id":     fixture.documentID,
		"key_version":     fixture.keyVersion,
		"source_url":      "https://objects.example/case/source.nsdw?sig=abc",
		"challenge_nonce": testNonce(),
	})
	return string(payload)
}

func extractRequestWith(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/v1/documents/x/extract", strings.NewReader(body))
}

func TestHandleDocumentExtractReadsTheDocument(t *testing.T) {
	srv, fixture, fetcher, model := extractServer(t)

	rec := httptest.NewRecorder()
	srv.handleDocumentExtract(rec, extractRequestWith(extractBody(fixture)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	var out extractResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not json: %v", err)
	}
	if out.DocumentID != fixture.documentID || out.SchemaID != "cbp_7501" {
		t.Fatalf("response lost the document or the schema: %+v", out)
	}
	if out.Fields["hts_10"] != "8207301500" || out.Fields["qty"] != float64(1200) {
		t.Fatalf("fields = %v", out.Fields)
	}
	if out.Model != "sealed-test-model" || out.ReceiptID == "" || len(out.SealedReceipt) == 0 {
		t.Fatalf("the read is not identifiable or not receipted: %+v", out)
	}

	// The confidence is measured from the tokens, not taken from the model's word.
	if out.ConfidenceSource != "logprobs" {
		t.Fatalf("confidence_source = %q, want logprobs", out.ConfidenceSource)
	}
	if out.Confidence["hts_10"] > 0.2 {
		t.Fatalf("hts_10 confidence = %v, but its weakest token was very unlikely", out.Confidence["hts_10"])
	}
	if out.Confidence["qty"] < 0.9 {
		t.Fatalf("qty confidence = %v, want close to 1", out.Confidence["qty"])
	}

	// The enclave fetched the ciphertext and opened it itself.
	if fetcher.url == "" {
		t.Fatal("the sealed object was never fetched")
	}
	// The document reached the model as text, and the model was constrained.
	if !strings.Contains(model.req.Prompt, "8207301500") {
		t.Fatal("the document text never reached the model")
	}
	if model.req.JSONSchema == "" || !model.req.Logprobs {
		t.Fatalf("the model was not constrained or not asked for logprobs: %+v", model.req)
	}
	if model.req.Stream {
		t.Fatal("extraction should not stream")
	}
}

func TestHandleDocumentExtractFeedsTheModelTheDecryptedDocument(t *testing.T) {
	srv, fixture, _, model := extractServer(t)
	stub := &textStub{}
	srv.text = stub

	rec := httptest.NewRecorder()
	srv.handleDocumentExtract(rec, extractRequestWith(extractBody(fixture)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	// What the text extractor was handed is the opened document, byte for byte.
	if !bytes.Equal(stub.gotPDF, []byte(testPDF)) {
		t.Fatalf("the text extractor got %q, want the decrypted document", stub.gotPDF)
	}
	if strings.Contains(model.req.Prompt, "NSD1") {
		t.Fatal("the sealed envelope, not the document, reached the model")
	}
}

func TestHandleDocumentExtractRefusesAnUnreadableOrWronglySealedDocument(t *testing.T) {
	srv, fixture, fetcher, _ := extractServer(t)

	t.Run("wrong key version", func(t *testing.T) {
		body := strings.Replace(extractBody(fixture), `"key_version":1`, `"key_version":9`, 1)
		rec := httptest.NewRecorder()
		srv.handleDocumentExtract(rec, extractRequestWith(body))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status %d, want 422", rec.Code)
		}
		if fetcher.url != "" {
			t.Fatal("the object was fetched before the key version was checked")
		}
	})

	t.Run("tampered envelope", func(t *testing.T) {
		saved := fetcher.blob
		tampered := bytes.Clone(saved)
		tampered[len(tampered)-1] ^= 0xff
		fetcher.blob = tampered
		defer func() { fetcher.blob = saved }()

		rec := httptest.NewRecorder()
		srv.handleDocumentExtract(rec, extractRequestWith(extractBody(fixture)))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status %d, want 422", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "tag") {
			t.Fatal("the internal decryption error leaked to the caller")
		}
	})

	t.Run("a page is not a document source", func(t *testing.T) {
		saved := fetcher.blob
		fetcher.blob = fixture.pages[0]
		defer func() { fetcher.blob = saved }()

		rec := httptest.NewRecorder()
		srv.handleDocumentExtract(rec, extractRequestWith(extractBody(fixture)))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status %d, want 422", rec.Code)
		}
	})

	t.Run("nothing at that url", func(t *testing.T) {
		saved := fetcher.err
		fetcher.err = errors.New("404 NoSuchKey")
		defer func() { fetcher.err = saved }()

		rec := httptest.NewRecorder()
		srv.handleDocumentExtract(rec, extractRequestWith(extractBody(fixture)))
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status %d, want 502", rec.Code)
		}
	})
}

func TestHandleDocumentExtractSaysWhenThereIsNoTextToRead(t *testing.T) {
	srv, fixture, _, _ := extractServer(t)
	srv.text = &textStub{err: render.ErrNoText}

	rec := httptest.NewRecorder()
	srv.handleDocumentExtract(rec, extractRequestWith(extractBody(fixture)))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no text layer") {
		t.Fatalf("body = %q, want it to say the document has no text", rec.Body.String())
	}
}

func TestHandleDocumentExtractRefusesBadRequests(t *testing.T) {
	srv, fixture, _, _ := extractServer(t)
	valid := extractBody(fixture)

	unusableSchema, err := json.Marshal(map[string]any{
		"schema_id":   "cbp_7501",
		"schema":      map[string]any{"type": "object"},
		"document_id": fixture.documentID,
		"key_version": fixture.keyVersion,
		"source_url":  "https://objects.example/case/source.nsdw?sig=abc",
	})
	if err != nil {
		t.Fatalf("build body: %v", err)
	}

	cases := map[string]struct {
		body   string
		status int
	}{
		"not json":        {body: "{nope", status: http.StatusBadRequest},
		"no schema_id":    {body: strings.Replace(valid, `"schema_id":"cbp_7501"`, `"schema_id":""`, 1), status: http.StatusBadRequest},
		"no source_url":   {body: strings.Replace(valid, `"source_url":"https://objects.example/case/source.nsdw?sig=abc"`, `"source_url":""`, 1), status: http.StatusBadRequest},
		"no key_version":  {body: strings.Replace(valid, `"key_version":1`, `"key_version":0`, 1), status: http.StatusBadRequest},
		"no document_id":  {body: strings.Replace(valid, `"document_id":"`+fixture.documentID+`"`, `"document_id":""`, 1), status: http.StatusBadRequest},
		"unusable schema": {body: string(unusableSchema), status: http.StatusBadRequest},
		"bad nonce":       {body: strings.Replace(valid, testNonce(), "abcd", 1), status: http.StatusBadRequest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.handleDocumentExtract(rec, extractRequestWith(tc.body))
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d (%s)", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
}

func TestHandleDocumentExtractReportsFailuresHonestly(t *testing.T) {
	srv, fixture, _, model := extractServer(t)

	t.Run("model fails", func(t *testing.T) {
		model.err = errors.New("connection refused")
		defer func() { model.err = nil }()

		rec := httptest.NewRecorder()
		srv.handleDocumentExtract(rec, extractRequestWith(extractBody(fixture)))
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status %d, want 502", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "connection refused") {
			t.Fatal("the internal inference error leaked to the caller")
		}
	})

	t.Run("model returns nonsense", func(t *testing.T) {
		model.content = "I could not read this document."
		defer func() { model.content = extractAnswer }()

		rec := httptest.NewRecorder()
		srv.handleDocumentExtract(rec, extractRequestWith(extractBody(fixture)))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status %d, want 422", rec.Code)
		}
	})

	t.Run("no key material", func(t *testing.T) {
		saved := srv.engine.Materials.SeedFor
		srv.engine.Materials.SeedFor = func(string) ([]byte, error) { return nil, keyscope.ErrNoKeyMaterial }
		defer func() { srv.engine.Materials.SeedFor = saved }()

		rec := httptest.NewRecorder()
		srv.handleDocumentExtract(rec, extractRequestWith(extractBody(fixture)))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status %d, want 403", rec.Code)
		}
	})

	t.Run("other methods", func(t *testing.T) {
		rec := httptest.NewRecorder()
		srv.handleDocumentExtract(rec, httptest.NewRequest(http.MethodGet, "/v1/documents/x/extract", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status %d, want 405", rec.Code)
		}
	})
}

func TestHandleDocumentExtractWithoutLogprobsSaysSoRatherThanGuessing(t *testing.T) {
	srv, fixture, _, model := extractServer(t)
	model.logprobs = nil

	rec := httptest.NewRecorder()
	srv.handleDocumentExtract(rec, extractRequestWith(extractBody(fixture)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	var out extractResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not json: %v", err)
	}
	if out.ConfidenceSource != "none" || out.Confidence != nil {
		t.Fatalf("an unmeasured read reported confidence: %+v", out)
	}
	if out.Fields["hts_10"] != "8207301500" {
		t.Fatal("the fields are still the answer even when the confidence is not measurable")
	}
}

func TestHandleDocumentExtractKeepsTheRecordWhenTheReceiptFails(t *testing.T) {
	srv, fixture, _, _ := extractServer(t)
	srv.engine.Seal = func(receipt.Input) (*receipt.SealedReceipt, error) {
		return nil, errors.New("attestation unavailable")
	}

	rec := httptest.NewRecorder()
	srv.handleDocumentExtract(rec, extractRequestWith(extractBody(fixture)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	var out extractResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not json: %v", err)
	}
	if out.ReceiptError == "" || out.ReceiptID != "" {
		t.Fatalf("a failed receipt was not recorded: %+v", out)
	}
	if out.Fields["hts_10"] != "8207301500" {
		t.Fatal("the read was lost because a receipt failed")
	}
}

func TestHandleDocumentExtractReceiptNamesTheDocumentAndSchema(t *testing.T) {
	srv, fixture, _, _ := extractServer(t)

	var seen receipt.Input
	srv.engine.Seal = func(in receipt.Input) (*receipt.SealedReceipt, error) {
		seen = in
		return &receipt.SealedReceipt{Package: receipt.Package{ReceiptID: "rcpt-extract"}}, nil
	}

	rec := httptest.NewRecorder()
	srv.handleDocumentExtract(rec, extractRequestWith(extractBody(fixture)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	if !strings.Contains(seen.Prompt, fixture.documentID) {
		t.Fatalf("the receipt does not name the document: %q", seen.Prompt)
	}
	if !strings.Contains(seen.Prompt, "schema=cbp_7501") || !strings.Contains(seen.Prompt, "key_version=1") {
		t.Fatalf("the receipt does not name the schema and key version: %q", seen.Prompt)
	}
	if !strings.Contains(seen.Response, "fields_sha256=") || !strings.Contains(seen.Response, "model=sealed-test-model") {
		t.Fatalf("the receipt does not cover the model and the fields: %q", seen.Response)
	}
	if strings.Contains(seen.Response, "8207301500") {
		t.Fatal("the receipt carries a field value in the clear")
	}
	if seen.ChallengeNonce != testNonce() {
		t.Fatalf("receipt nonce = %q", seen.ChallengeNonce)
	}
}

func TestHandleDocumentExtractRouteCarriesTheDocumentID(t *testing.T) {
	srv, fixture, _, _ := extractServer(t)

	// The body deliberately omits document_id: it comes from the path.
	payload, _ := json.Marshal(map[string]any{
		"schema_id":   "cbp_7501",
		"schema":      json.RawMessage(extractSchema),
		"key_version": fixture.keyVersion,
		"source_url":  "https://objects.example/case/source.nsdw?sig=abc",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/documents/{document_id}/extract", srv.handleDocumentExtract)

	req := httptest.NewRequest(http.MethodPost, "/v1/documents/"+fixture.documentID+"/extract", strings.NewReader(string(payload)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out extractResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not json: %v", err)
	}
	if out.DocumentID != fixture.documentID {
		t.Fatalf("document id = %q, want the one in the path", out.DocumentID)
	}

	t.Run("a mismatched body id is refused", func(t *testing.T) {
		mismatch := strings.Replace(string(payload), `"schema_id"`, `"document_id":"someone-elses-document","schema_id"`, 1)
		req := httptest.NewRequest(http.MethodPost, "/v1/documents/"+fixture.documentID+"/extract", strings.NewReader(mismatch))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", rec.Code)
		}
	})
}

func TestCanonicalExtractLinesAreStable(t *testing.T) {
	prompt := canonicalExtractPrompt("abc", "cbp_7501", 2, 3)
	if prompt != "sealed-document/1|document.extract|id=abc|schema=cbp_7501|key_version=2|pages=3" {
		t.Fatalf("prompt = %q", prompt)
	}

	line := canonicalExtractResponse("m", map[string]any{"qty": 1200}, map[string]float64{"qty": 0.9})
	if !strings.HasPrefix(line, "sealed-document/1|document.extract|model=m|fields_sha256=") {
		t.Fatalf("response = %q", line)
	}
	if !strings.HasSuffix(line, `confidence={"qty":0.9}`) {
		t.Fatalf("response does not carry the measured confidence: %q", line)
	}

	unmeasured := canonicalExtractResponse("m", map[string]any{"qty": 1200}, nil)
	if !strings.HasSuffix(unmeasured, "confidence=none") {
		t.Fatalf("an unmeasured read is not marked as such: %q", unmeasured)
	}
}
