package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"nexqloud-sealed/internal/blobfetch"
	"nexqloud-sealed/internal/documents"
	"nexqloud-sealed/internal/identity"
	"nexqloud-sealed/internal/inference"
	"nexqloud-sealed/internal/readkey"
	"nexqloud-sealed/internal/render"
	"nexqloud-sealed/pkg/docwire"
)

// TestHandleDocumentIngestWithTheRealConverter runs the whole path with poppler
// itself rather than a fake: a real PDF in, real page renders, sealed, out as a
// container, then back open again with the key the shim derived.
//
// It skips unless it is pointed at a document and the guest's converter is
// present, so CI stays green while anyone can reproduce it:
//
//	NEXQLOUD_TEST_PDF=/path/to/entry-summary.pdf go test ./cmd/shim/ -run RealConverter -v
func TestHandleDocumentIngestWithTheRealConverter(t *testing.T) {
	pdfPath := os.Getenv("NEXQLOUD_TEST_PDF")
	if pdfPath == "" {
		t.Skip("set NEXQLOUD_TEST_PDF to a real PDF to run the end-to-end ingest")
	}
	if _, err := exec.LookPath("pdftoppm"); err != nil {
		t.Skip("no poppler on this host; the guest image provides it")
	}

	pdf, err := os.ReadFile(pdfPath)
	if err != nil {
		t.Fatalf("read %s: %v", pdfPath, err)
	}

	srv, _ := ingestServer(t, 0)
	srv.renderer = &render.Exec{} // the real converter, as the guest runs it

	rec := httptest.NewRecorder()
	srv.handleDocumentIngest(rec, ingestRequest(pdf, testNonce()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	header, source, pages, err := docwire.Decode(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if want := documents.Fingerprint(pdf); header.DocumentID != want {
		t.Fatalf("DocumentID = %s, want the plaintext hash %s", header.DocumentID, want)
	}
	if len(pages) == 0 {
		t.Fatal("poppler rendered no pages")
	}
	// The container holds ciphertext: a page image must not be recognisable as one.
	for i, page := range pages {
		if bytes.HasPrefix(page, []byte("\x89PNG\r\n\x1a\n")) {
			t.Fatalf("page %d travelled as a plain image", i+1)
		}
		if bytes.Contains(page, pdf[:32]) {
			t.Fatalf("page %d contains document bytes", i+1)
		}
	}
	t.Logf("rendered and sealed %d page(s) of %s; container %d bytes", len(pages), pdfPath, rec.Body.Len())

	// The document comes back only under the key this shim derived, byte for byte.
	dek, keyVersion, err := srv.engine.DEK(identity.DevIdentity(""))
	if err != nil {
		t.Fatalf("DEK: %v", err)
	}
	opened, openedPages, err := documents.OpenDocument(dek, documents.Sealed{
		Fingerprint: header.DocumentID,
		KeyVersion:  keyVersion,
		Source:      source,
		Pages:       pages,
	})
	if err != nil {
		t.Fatalf("OpenDocument: %v", err)
	}
	gotSum, wantSum := sha256.Sum256(opened), sha256.Sum256(pdf)
	if gotSum != wantSum {
		t.Fatalf("opened document differs from the original: %s vs %s",
			hex.EncodeToString(gotSum[:8]), hex.EncodeToString(wantSum[:8]))
	}
	// Opened, the pages are the renders poppler actually produced.
	for i, page := range openedPages {
		if !bytes.HasPrefix(page, []byte("\x89PNG\r\n\x1a\n")) {
			t.Fatalf("opened page %d is not a PNG", i+1)
		}
	}
	t.Logf("opened %d page(s), first is %d bytes", len(openedPages), len(openedPages[0]))
}

// recordingInference stands in for the model but records the prompt it was given,
// so a test can prove what the enclave actually sent it.
type recordingInference struct {
	stub   *stubInference
	prompt string
}

func (r *recordingInference) Complete(req inference.Request) (inference.Response, error) {
	r.prompt = req.Prompt
	return r.stub.Complete(req)
}

// TestHandleDocumentExtractWithTheRealConverter runs a real document through the
// whole pipeline: rendered by poppler, sealed, kept outside the process, fetched
// back by URL, opened with the derived key, read by poppler's text extractor, and
// measured from the engine's token probabilities.
//
// Only the model is a stand-in. It is the one part of this that needs an enclosure
// this host does not have.
//
//	NEXQLOUD_TEST_PDF=/path/to/entry-summary.pdf go test ./cmd/shim/ -run RealConverter -v
func TestHandleDocumentExtractWithTheRealConverter(t *testing.T) {
	pdfPath := os.Getenv("NEXQLOUD_TEST_PDF")
	if pdfPath == "" {
		t.Skip("set NEXQLOUD_TEST_PDF to a real PDF to run the end-to-end extraction")
	}
	if _, err := exec.LookPath("pdftotext"); err != nil {
		t.Skip("no poppler on this host; the guest image provides it")
	}

	pdf, err := os.ReadFile(pdfPath)
	if err != nil {
		t.Fatalf("read %s: %v", pdfPath, err)
	}

	srv, _ := ingestServer(t, 0)
	srv.renderer = &render.Exec{}

	// Ingest with the real renderer, as the calling application would.
	ingest := httptest.NewRecorder()
	srv.handleDocumentIngest(ingest, ingestRequest(pdf, testNonce()))
	if ingest.Code != http.StatusOK {
		t.Fatalf("ingest status %d: %s", ingest.Code, ingest.Body.String())
	}
	header, source, _, err := docwire.Decode(bytes.NewReader(ingest.Body.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	// Put the ciphertext where a caller keeps it, and hand the enclave a URL.
	objects := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(source)
	}))
	defer objects.Close()

	model := &recordingInference{stub: &stubInference{content: extractAnswer, logprobs: answerTokens()}}
	srv.engine.Inference = model
	srv.text = &render.ExecText{}
	srv.fetcher = &blobfetch.Fetcher{AllowPlainHTTP: true}

	body, err := json.Marshal(map[string]any{
		"schema_id":   "cbp_7501",
		"schema":      json.RawMessage(extractSchema),
		"document_id": header.DocumentID,
		"key_version": header.KeyVersion,
		"source_url":  objects.URL + "/" + header.DocumentID + ".nsdw",
	})
	if err != nil {
		t.Fatalf("build body: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.handleDocumentExtract(rec, extractRequestWith(string(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("extract status %d: %s", rec.Code, rec.Body.String())
	}

	// What this document's text layer actually says, read the same way the enclave
	// reads it. Comparing against the real extraction keeps the test honest for any
	// document it is pointed at, instead of hard-coding one file's contents.
	expected, err := exec.Command("pdftotext", "-layout", pdfPath, "-").Output()
	if err != nil {
		t.Fatalf("pdftotext on the test document: %v", err)
	}
	marker := ""
	for _, line := range strings.Split(string(expected), "\n") {
		if line = strings.TrimSpace(line); len(line) >= 8 {
			marker = line
			break
		}
	}
	if marker == "" {
		t.Skip("the test document has no text layer to look for")
	}

	var out extractResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not json: %v", err)
	}
	if out.DocumentID != header.DocumentID {
		t.Fatalf("document id = %q, want %q", out.DocumentID, header.DocumentID)
	}
	if out.Pages < 1 {
		t.Fatalf("pages = %d; the real document was not read", out.Pages)
	}
	// The real text layer of the real document reached the model.
	if !strings.Contains(model.prompt, marker) {
		t.Fatalf("the document's own text (%q) did not reach the model:\n%s", marker, firstLines(model.prompt, 12))
	}
	if out.ConfidenceSource != "logprobs" || out.Confidence == nil {
		t.Fatalf("confidence_source = %q, confidence = %v", out.ConfidenceSource, out.Confidence)
	}
	if out.ReceiptID == "" {
		t.Fatal("the read carries no receipt")
	}
	t.Logf("read %s: %d page(s), fields=%v, confidence=%v (%s)",
		pdfPath, out.Pages, out.Fields, out.Confidence, out.ConfidenceSource)
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// TestHandleDocumentReadKeyWithTheRealConverter runs the review path end to end on
// a real document: ingested and rendered by poppler, stored as ciphertext, fetched
// by URL, re-sealed to a browser's own key, and opened by that browser — while the
// bytes the application holds stay unreadable.
//
//	NEXQLOUD_TEST_PDF=/path/to/entry-summary.pdf go test ./cmd/shim/ -run RealConverter -v
func TestHandleDocumentReadKeyWithTheRealConverter(t *testing.T) {
	pdfPath := os.Getenv("NEXQLOUD_TEST_PDF")
	if pdfPath == "" {
		t.Skip("set NEXQLOUD_TEST_PDF to a real PDF to run the end-to-end review path")
	}

	pdf, err := os.ReadFile(pdfPath)
	if err != nil {
		t.Fatalf("read %s: %v", pdfPath, err)
	}

	srv, _ := ingestServer(t, 0)
	srv.renderer = &render.Exec{}

	// 1. The customer's document goes in.
	ingest := httptest.NewRecorder()
	srv.handleDocumentIngest(ingest, ingestRequest(pdf, testNonce()))
	if ingest.Code != http.StatusOK {
		t.Fatalf("ingest status %d: %s", ingest.Code, ingest.Body.String())
	}
	header, _, sealedPages, err := docwire.Decode(bytes.NewReader(ingest.Body.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(sealedPages) == 0 {
		t.Fatal("the ingested document has no page renders")
	}

	// What the enclave itself would show, for comparison.
	id := identity.DevIdentity("")
	dek, keyVersion, err := srv.engine.DEK(id)
	if err != nil {
		t.Fatalf("DEK: %v", err)
	}
	wantPages := make([][]byte, 0, len(sealedPages))
	for i, sealed := range sealedPages {
		kind, page, err := documents.Open(dek, sealed, keyVersion)
		if err != nil || kind != documents.KindPage {
			t.Fatalf("open page %d: %v (kind %v)", i+1, err, kind)
		}
		wantPages = append(wantPages, page)
	}

	// 2. The application stores the container and serves it from its bucket.
	objects := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(ingest.Body.Bytes())
	}))
	defer objects.Close()

	// 3. A reviewer's browser asks for a page with its own public key.
	reviewer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("browser key: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"document_id":          header.DocumentID,
		"purpose":              "review",
		"ttl_seconds":          120,
		"recipient_public_key": base64.StdEncoding.EncodeToString(reviewer.PublicKey().Bytes()),
		"source_url":           objects.URL + "/" + header.DocumentID + ".nsdw",
	})
	if err != nil {
		t.Fatalf("build body: %v", err)
	}
	srv.fetcher = &blobfetch.Fetcher{AllowPlainHTTP: true}

	rec := httptest.NewRecorder()
	srv.handleDocumentReadKey(rec, readKeyHTTPRequest(string(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("read-key status %d: %s", rec.Code, rec.Body.String())
	}

	// 4. The application relays those bytes and can read none of them.
	held := rec.Body.Bytes()
	for i, page := range bytes.Split(held, []byte("\x89PNG\r\n\x1a\n")) {
		if i > 0 && len(page) > len(wantPages[0])/2 {
			t.Fatal("a full page image is readable straight out of the relayed bytes")
		}
	}

	grantHeader, grantBlob, grantedPages, err := docwire.Decode(bytes.NewReader(held))
	if err != nil {
		t.Fatalf("the response is not a container: %v", err)
	}
	var grant readkey.Wrapped
	if err := json.Unmarshal(grantBlob, &grant); err != nil {
		t.Fatalf("the first part is not a grant: %v", err)
	}
	if grant.TTLSeconds != 120 || grantHeader.ReceiptID == "" {
		t.Fatalf("grant = %+v (receipt %q)", grant, grantHeader.ReceiptID)
	}

	// 5. The browser opens the key and the page.
	sessionKey, err := readkey.Open(reviewer, grant)
	if err != nil {
		t.Fatalf("the browser could not open its grant: %v", err)
	}
	if len(grantedPages) != len(wantPages) {
		t.Fatalf("granted %d pages, the document has %d", len(grantedPages), len(wantPages))
	}
	for i, sealed := range grantedPages {
		page, err := readkey.OpenPage(sessionKey, sealed)
		if err != nil {
			t.Fatalf("the browser could not open page %d: %v", i+1, err)
		}
		if !bytes.Equal(page, wantPages[i]) {
			t.Fatalf("page %d is not the render the enclave made", i+1)
		}
	}

	t.Logf("review path: %s, %d page(s), first render %d bytes, opened by the browser byte-for-byte",
		pdfPath, len(grantedPages), len(wantPages[0]))
}
