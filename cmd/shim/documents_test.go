package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"nexqloud-sealed/internal/documents"
	"nexqloud-sealed/internal/identity"
	"nexqloud-sealed/internal/keyscope"
	"nexqloud-sealed/internal/receipt"
	"nexqloud-sealed/internal/render"
	"nexqloud-sealed/pkg/docwire"
)

const testPDF = "%PDF-1.4\ntest document body\n"

func testNonce() string { return strings.Repeat("ab", 32) }

type fakeRenderer struct {
	pages  [][]byte
	err    error
	calls  int
	gotPDF []byte
}

func (f *fakeRenderer) Pages(_ context.Context, pdf []byte, _ render.Options) ([][]byte, error) {
	f.calls++
	f.gotPDF = pdf
	return f.pages, f.err
}

func pngPage(label string) []byte {
	return []byte("\x89PNG\r\n\x1a\n" + label)
}

// ingestServer is a shim wired for the document path: a body that renders, and a
// limit small enough to exercise.
func ingestServer(t *testing.T, pages int) (*server, *fakeRenderer) {
	t.Helper()
	srv := testHTTPServer(t)

	rendered := make([][]byte, 0, pages)
	for i := 1; i <= pages; i++ {
		rendered = append(rendered, pngPage("page "+string(rune('0'+i))))
	}
	fake := &fakeRenderer{pages: rendered}
	srv.renderer = fake
	srv.maxDocumentBytes = 1 << 20
	return srv, fake
}

func ingestRequest(body []byte, nonce string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/documents/ingest", bytes.NewReader(body))
	if nonce != "" {
		req.Header.Set(HeaderChallengeNonce, nonce)
	}
	return req
}

func TestHandleDocumentIngestRoundTrip(t *testing.T) {
	srv, fake := ingestServer(t, 2)

	rec := httptest.NewRecorder()
	srv.handleDocumentIngest(rec, ingestRequest([]byte(testPDF), testNonce()))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != docwire.ContentType {
		t.Fatalf("Content-Type = %q, want %q", got, docwire.ContentType)
	}
	if fake.calls != 1 || !bytes.Equal(fake.gotPDF, []byte(testPDF)) {
		t.Fatal("the renderer did not receive the document body")
	}

	header, source, pages, err := docwire.Decode(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if header.DocumentID != documents.Fingerprint([]byte(testPDF)) {
		t.Fatalf("DocumentID = %q, want the plaintext fingerprint", header.DocumentID)
	}
	if header.KeyVersion != 1 || header.ReceiptID == "" || len(header.Receipt) == 0 {
		t.Fatalf("header incomplete: %+v", header)
	}
	if len(pages) != 2 {
		t.Fatalf("got %d pages, want 2", len(pages))
	}

	// The document is sealed under the key this server derives for this identity.
	// Opening it with anything else must fail.
	id := identity.DevIdentity("")
	dek, keyVersion, err := srv.engine.DEK(id)
	if err != nil {
		t.Fatalf("DEK: %v", err)
	}
	if keyVersion != header.KeyVersion {
		t.Fatalf("envelope records v%d but the key is v%d", header.KeyVersion, keyVersion)
	}

	opened, openedPages, err := documents.OpenDocument(dek, documents.Sealed{
		Fingerprint: header.DocumentID,
		KeyVersion:  header.KeyVersion,
		Source:      source,
		Pages:       pages,
	})
	if err != nil {
		t.Fatalf("OpenDocument: %v", err)
	}
	if !bytes.Equal(opened, []byte(testPDF)) {
		t.Fatalf("opened document = %q", opened)
	}
	if !bytes.Equal(openedPages[0], pngPage("page 1")) {
		t.Fatal("opened page does not match what the renderer produced")
	}

	if _, _, err := documents.OpenDocument(bytes.Repeat([]byte{0x09}, 32), documents.Sealed{
		Fingerprint: header.DocumentID,
		KeyVersion:  header.KeyVersion,
		Source:      source,
		Pages:       pages,
	}); err == nil {
		t.Fatal("a document opened with the wrong key")
	}
}

func TestHandleDocumentIngestReceiptBindsTheDocument(t *testing.T) {
	srv, _ := ingestServer(t, 1)

	var seen receipt.Input
	srv.engine.Seal = func(in receipt.Input) (*receipt.SealedReceipt, error) {
		seen = in
		return &receipt.SealedReceipt{Package: receipt.Package{ReceiptID: "rcpt-doc"}}, nil
	}

	rec := httptest.NewRecorder()
	srv.handleDocumentIngest(rec, ingestRequest([]byte(testPDF), testNonce()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	fingerprint := documents.Fingerprint([]byte(testPDF))
	if !strings.Contains(seen.Prompt, fingerprint) {
		t.Fatalf("receipt prompt does not name the document: %q", seen.Prompt)
	}
	if !strings.Contains(seen.Prompt, "key_version=1") || !strings.Contains(seen.Prompt, "pages=1") {
		t.Fatalf("receipt prompt does not carry the key version or page count: %q", seen.Prompt)
	}
	if !strings.Contains(seen.Response, "source_sha256=") {
		t.Fatalf("receipt response does not cover the sealed bytes: %q", seen.Response)
	}
	if seen.ChallengeNonce != testNonce() {
		t.Fatalf("receipt nonce = %q, want the request nonce", seen.ChallengeNonce)
	}
	// The receipt carries the same claim hash the chat path passes. A dev identity
	// is built without a JWT and so has an empty one; the builder substitutes its
	// placeholder exactly as it does for chat, which is why this asserts agreement
	// with the identity rather than a non-empty string.
	if want := identity.DevIdentity("").Hash; seen.IdentityClaimHash != want {
		t.Fatalf("receipt claim hash = %q, want %q", seen.IdentityClaimHash, want)
	}

	header, _, _, err := docwire.Decode(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if header.ReceiptID != "rcpt-doc" {
		t.Fatalf("header receipt id = %q", header.ReceiptID)
	}
}

func TestHandleDocumentIngestKeepsDocumentWhenReceiptFails(t *testing.T) {
	srv, _ := ingestServer(t, 1)
	srv.engine.Seal = func(receipt.Input) (*receipt.SealedReceipt, error) {
		return nil, errors.New("attestation unavailable")
	}

	rec := httptest.NewRecorder()
	srv.handleDocumentIngest(rec, ingestRequest([]byte(testPDF), testNonce()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	header, _, _, err := docwire.Decode(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("the sealed document was lost because a receipt failed: %v", err)
	}
	if header.Error == "" || header.ReceiptID != "" {
		t.Fatalf("header = %+v, want a recorded receipt failure", header)
	}
}

func TestHandleDocumentIngestValidatesNonceWhenPresent(t *testing.T) {
	srv, _ := ingestServer(t, 1)

	// A nonce is optional on every sealed door: supply one to bind the receipt to a
	// challenge you issued, or leave it out and the enclave generates one.
	rec := httptest.NewRecorder()
	srv.handleDocumentIngest(rec, ingestRequest([]byte(testPDF), ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("missing nonce: status %d, want 200", rec.Code)
	}

	for name, nonce := range map[string]string{"too short": "abcd", "not hex": strings.Repeat("zz", 32)} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.handleDocumentIngest(rec, ingestRequest([]byte(testPDF), nonce))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", rec.Code)
			}
		})
	}
}

func TestHandleDocumentIngestRefusesNonPDF(t *testing.T) {
	srv, _ := ingestServer(t, 1)
	srv.renderer = &fakeRenderer{err: render.ErrNotPDF}

	rec := httptest.NewRecorder()
	srv.handleDocumentIngest(rec, ingestRequest([]byte("a spreadsheet, probably"), testNonce()))
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status %d, want 415", rec.Code)
	}
}

func TestHandleDocumentIngestRendererFailure(t *testing.T) {
	srv, _ := ingestServer(t, 1)
	srv.renderer = &fakeRenderer{err: errors.New("pdftoppm exploded")}

	rec := httptest.NewRecorder()
	srv.handleDocumentIngest(rec, ingestRequest([]byte(testPDF), testNonce()))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "pdftoppm") {
		t.Fatal("the internal renderer error leaked to the caller")
	}
}

func TestHandleDocumentIngestNoKeyMaterial(t *testing.T) {
	srv, _ := ingestServer(t, 1)
	srv.engine.Materials.SeedFor = func(string) ([]byte, error) {
		return nil, keyscope.ErrNoKeyMaterial
	}

	rec := httptest.NewRecorder()
	srv.handleDocumentIngest(rec, ingestRequest([]byte(testPDF), testNonce()))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
}

func TestHandleDocumentIngestRejectsEmptyAndOversizedBodies(t *testing.T) {
	srv, _ := ingestServer(t, 1)

	rec := httptest.NewRecorder()
	srv.handleDocumentIngest(rec, ingestRequest(nil, testNonce()))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body: status %d, want 400", rec.Code)
	}

	srv.maxDocumentBytes = 16
	rec = httptest.NewRecorder()
	srv.handleDocumentIngest(rec, ingestRequest([]byte(testPDF), testNonce()))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: status %d, want 413", rec.Code)
	}
}

func TestHandleDocumentIngestRejectsOtherMethods(t *testing.T) {
	srv, _ := ingestServer(t, 1)

	rec := httptest.NewRecorder()
	srv.handleDocumentIngest(rec, httptest.NewRequest(http.MethodGet, "/v1/documents/ingest", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want 405", rec.Code)
	}
}

func TestCanonicalReceiptLinesAreStable(t *testing.T) {
	prompt := canonicalIngestPrompt("abc", 1, 100, 2)
	if prompt != "sealed-document/1|document.ingest|id=abc|key_version=1|source_bytes=100|pages=2" {
		t.Fatalf("prompt = %q", prompt)
	}
	response := canonicalIngestResponse("deadbeef", []string{"aa", "bb"}, 4096)
	if response != "sealed-document/1|document.ingest|source_sha256=deadbeef|pages=aa,bb|sealed_bytes=4096" {
		t.Fatalf("response = %q", response)
	}
}

func TestRenderDefaultsToTheGuestConverter(t *testing.T) {
	if _, err := exec.LookPath("pdftoppm"); err == nil {
		t.Skip("this workstation has pdftoppm installed; the guest fallback is covered in internal/render")
	}
	srv, _ := ingestServer(t, 1)
	srv.renderer = nil

	rec := httptest.NewRecorder()
	// With no renderer configured the handler falls back to the guest's own
	// converter, which is absent here — so the document is refused, not invented.
	srv.handleDocumentIngest(rec, ingestRequest([]byte(testPDF), testNonce()))
	if rec.Code == http.StatusOK {
		t.Fatal("ingest succeeded with no converter present")
	}
}
