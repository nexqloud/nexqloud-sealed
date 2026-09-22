package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nexqloud-sealed/internal/keyscope"
	"nexqloud-sealed/internal/readkey"
	"nexqloud-sealed/internal/receipt"
	"nexqloud-sealed/pkg/docwire"
)

// browser is a reviewer's browser: it holds the private half and shares only the
// public half, exactly as the application relaying the request would see it.
type browser struct {
	key *ecdh.PrivateKey
}

func newBrowser(t *testing.T) *browser {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("browser key: %v", err)
	}
	return &browser{key: key}
}

func (b *browser) publicKey(t *testing.T) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(b.key.PublicKey().Bytes())
}

func readKeyServer(t *testing.T) (*server, string, int, []byte, *fakeFetcher) {
	t.Helper()
	srv := testHTTPServer(t)

	fixture := sealFixture(t, srv)

	// What the calling application keeps in its bucket: the container ingest
	// returned, sealed pages and all.
	var container bytes.Buffer
	if err := docwire.Encode(&container, docwire.Header{
		DocumentID: fixture.documentID,
		KeyVersion: fixture.keyVersion,
	}, fixture.envelope, fixture.pages); err != nil {
		t.Fatalf("encode container: %v", err)
	}

	fetcher := &fakeFetcher{blob: container.Bytes()}
	srv.fetcher = fetcher
	return srv, fixture.documentID, fixture.keyVersion, container.Bytes(), fetcher
}

func readKeyBody(documentID string, browser *browser, mutate func(map[string]any)) string {
	payload := map[string]any{
		"document_id":          documentID,
		"purpose":              "review",
		"ttl_seconds":          300,
		"recipient_public_key": base64.StdEncoding.EncodeToString(browser.key.PublicKey().Bytes()),
		"source_url":           "https://objects.example/case/source.nsdw?sig=abc",
		"challenge_nonce":      testNonce(),
	}
	if mutate != nil {
		mutate(payload)
	}
	raw, _ := json.Marshal(payload)
	return string(raw)
}

func readKeyHTTPRequest(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/v1/documents/x/read-key", strings.NewReader(body))
}

func TestHandleDocumentReadKeyGivesTheBrowserAPageItCanOpen(t *testing.T) {
	srv, documentID, keyVersion, _, fetcher := readKeyServer(t)
	reviewer := newBrowser(t)

	rec := httptest.NewRecorder()
	srv.handleDocumentReadKey(rec, readKeyHTTPRequest(readKeyBody(documentID, reviewer, nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != docwire.ContentType {
		t.Fatalf("content-type = %q, want the container type", ct)
	}
	if fetcher.url == "" {
		t.Fatal("the sealed document was never fetched")
	}

	header, grantBlob, sealedPages, err := docwire.Decode(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("the response is not a container: %v", err)
	}
	if header.DocumentID != documentID || header.KeyVersion != keyVersion {
		t.Fatalf("container header = %+v", header)
	}
	if len(sealedPages) != 1 {
		t.Fatalf("container carries %d pages", len(sealedPages))
	}

	var grant readkey.Wrapped
	if err := json.Unmarshal(grantBlob, &grant); err != nil {
		t.Fatalf("the first part is not a grant: %v", err)
	}
	if grant.DocumentID != documentID || grant.Purpose != "review" || grant.TTLSeconds != 300 {
		t.Fatalf("grant = %+v", grant)
	}

	// The browser opens the key and reads the page.
	sessionKey, err := readkey.Open(reviewer.key, grant)
	if err != nil {
		t.Fatalf("the browser could not open its own grant: %v", err)
	}
	page, err := readkey.OpenPage(sessionKey, sealedPages[0])
	if err != nil {
		t.Fatalf("the browser could not open the page: %v", err)
	}
	if !bytes.Equal(page, pngPage("page 1")) {
		t.Fatal("the page the browser read is not the render the enclave sealed")
	}
	if header.ReceiptID == "" {
		t.Fatal("the grant was not receipted")
	}
}

func TestHandleDocumentReadKeyLeavesTheApplicationBlind(t *testing.T) {
	srv, documentID, _, _, _ := readKeyServer(t)
	reviewer := newBrowser(t)

	rec := httptest.NewRecorder()
	srv.handleDocumentReadKey(rec, readKeyHTTPRequest(readKeyBody(documentID, reviewer, nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	// Everything the calling application holds after relaying this.
	held := rec.Body.Bytes()
	_, grantBlob, sealedPages, err := docwire.Decode(bytes.NewReader(held))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	t.Run("the pages are not pages", func(t *testing.T) {
		for i, page := range sealedPages {
			if bytes.HasPrefix(page, []byte("\x89PNG\r\n\x1a\n")) {
				t.Fatalf("page %d is a readable PNG", i+1)
			}
			if bytes.Contains(page, []byte("page 1")) {
				t.Fatalf("page %d carries its plaintext", i+1)
			}
		}
	})

	t.Run("the grant is not openable by the application", func(t *testing.T) {
		// The application has the grant but not the browser's private half.
		applicationsKey, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		var grant readkey.Wrapped
		if err := json.Unmarshal(grantBlob, &grant); err != nil {
			t.Fatalf("grant: %v", err)
		}
		if key, err := readkey.Open(applicationsKey, grant); err == nil {
			t.Fatalf("the application recovered a %d-byte session key", len(key))
		}
	})

	t.Run("no session key appears anywhere in the bytes it holds", func(t *testing.T) {
		var grant readkey.Wrapped
		if err := json.Unmarshal(grantBlob, &grant); err != nil {
			t.Fatalf("grant: %v", err)
		}
		sessionKey, err := readkey.Open(reviewer.key, grant)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if bytes.Contains(held, sessionKey) {
			t.Fatal("the session key is in the container in the clear")
		}
		if strings.Contains(string(held), base64.StdEncoding.EncodeToString(sessionKey)) {
			t.Fatal("the session key is in the container base64-encoded")
		}
	})
}

func TestHandleDocumentReadKeyRefusesBadRequests(t *testing.T) {
	srv, documentID, _, _, _ := readKeyServer(t)
	reviewer := newBrowser(t)

	junk := make([]byte, 65)
	if _, err := rand.Read(junk); err != nil {
		t.Fatalf("rand: %v", err)
	}

	cases := map[string]struct {
		body   string
		status int
	}{
		"not json":            {body: "{nope", status: http.StatusBadRequest},
		"no document":         {body: readKeyBody("", reviewer, nil), status: http.StatusBadRequest},
		"no source_url":       {body: readKeyBody(documentID, reviewer, func(m map[string]any) { m["source_url"] = "" }), status: http.StatusBadRequest},
		"no recipient key":    {body: readKeyBody(documentID, reviewer, func(m map[string]any) { m["recipient_public_key"] = "" }), status: http.StatusBadRequest},
		"recipient not a key": {body: readKeyBody(documentID, reviewer, func(m map[string]any) { m["recipient_public_key"] = base64.StdEncoding.EncodeToString(junk) }), status: http.StatusBadRequest},
		"unknown purpose":     {body: readKeyBody(documentID, reviewer, func(m map[string]any) { m["purpose"] = "admin" }), status: http.StatusBadRequest},
		"bad nonce":           {body: strings.Replace(readKeyBody(documentID, reviewer, nil), testNonce(), "abcd", 1), status: http.StatusBadRequest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.handleDocumentReadKey(rec, readKeyHTTPRequest(tc.body))
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d (%s)", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
}

func TestHandleDocumentReadKeyAnUnstatedPurposeIsReview(t *testing.T) {
	srv, documentID, _, _, _ := readKeyServer(t)
	reviewer := newBrowser(t)

	body := readKeyBody(documentID, reviewer, func(m map[string]any) { delete(m, "purpose") })
	rec := httptest.NewRecorder()
	srv.handleDocumentReadKey(rec, readKeyHTTPRequest(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	_, grantBlob, _, err := docwire.Decode(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var grant readkey.Wrapped
	if err := json.Unmarshal(grantBlob, &grant); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if grant.Purpose != readkey.PurposeReview {
		t.Fatalf("purpose = %q, want review", grant.Purpose)
	}
}

func TestHandleDocumentReadKeyCutsALifetimeToTheBounds(t *testing.T) {
	srv, documentID, _, _, _ := readKeyServer(t)
	reviewer := newBrowser(t)

	for name, tc := range map[string]struct {
		seconds int
		want    int
	}{
		"asked for nothing": {seconds: 0, want: int(readkey.DefaultTTL.Seconds())},
		"asked for an hour": {seconds: 3600, want: int(readkey.MaxTTL.Seconds())},
		"asked for a blink": {seconds: 1, want: int(readkey.MinTTL.Seconds())},
		"asked for sane":    {seconds: 240, want: 240},
	} {
		t.Run(name, func(t *testing.T) {
			body := readKeyBody(documentID, reviewer, func(m map[string]any) { m["ttl_seconds"] = tc.seconds })
			rec := httptest.NewRecorder()
			srv.handleDocumentReadKey(rec, readKeyHTTPRequest(body))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			_, grantBlob, _, err := docwire.Decode(bytes.NewReader(rec.Body.Bytes()))
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			var grant readkey.Wrapped
			if err := json.Unmarshal(grantBlob, &grant); err != nil {
				t.Fatalf("grant: %v", err)
			}
			if grant.TTLSeconds != tc.want {
				t.Fatalf("ttl = %d, want %d", grant.TTLSeconds, tc.want)
			}
		})
	}
}

func TestHandleDocumentReadKeyRefusesADocumentItCannotRead(t *testing.T) {
	srv, documentID, keyVersion, _, fetcher := readKeyServer(t)
	reviewer := newBrowser(t)

	t.Run("wrong key version", func(t *testing.T) {
		saved := fetcher.blob
		var container bytes.Buffer
		fixture := sealFixture(t, srv)
		if err := docwire.Encode(&container, docwire.Header{DocumentID: documentID, KeyVersion: keyVersion + 9}, fixture.envelope, fixture.pages); err != nil {
			t.Fatalf("encode: %v", err)
		}
		fetcher.blob = container.Bytes()
		defer func() { fetcher.blob = saved }()

		rec := httptest.NewRecorder()
		srv.handleDocumentReadKey(rec, readKeyHTTPRequest(readKeyBody(documentID, reviewer, nil)))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status %d, want 422", rec.Code)
		}
	})

	t.Run("no pages to show", func(t *testing.T) {
		saved := fetcher.blob
		fixture := sealFixture(t, srv)
		var container bytes.Buffer
		if err := docwire.Encode(&container, docwire.Header{DocumentID: documentID, KeyVersion: keyVersion}, fixture.envelope, nil); err != nil {
			t.Fatalf("encode: %v", err)
		}
		fetcher.blob = container.Bytes()
		defer func() { fetcher.blob = saved }()

		rec := httptest.NewRecorder()
		srv.handleDocumentReadKey(rec, readKeyHTTPRequest(readKeyBody(documentID, reviewer, nil)))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status %d, want 422", rec.Code)
		}
	})

	t.Run("a source envelope passed off as a page", func(t *testing.T) {
		saved := fetcher.blob
		fixture := sealFixture(t, srv)
		var container bytes.Buffer
		if err := docwire.Encode(&container, docwire.Header{DocumentID: documentID, KeyVersion: keyVersion}, fixture.envelope, [][]byte{fixture.envelope}); err != nil {
			t.Fatalf("encode: %v", err)
		}
		fetcher.blob = container.Bytes()
		defer func() { fetcher.blob = saved }()

		rec := httptest.NewRecorder()
		srv.handleDocumentReadKey(rec, readKeyHTTPRequest(readKeyBody(documentID, reviewer, nil)))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status %d, want 422", rec.Code)
		}
	})

	t.Run("stored bytes are not a container", func(t *testing.T) {
		saved := fetcher.blob
		fetcher.blob = []byte("%PDF-1.7 not a container at all")
		defer func() { fetcher.blob = saved }()

		rec := httptest.NewRecorder()
		srv.handleDocumentReadKey(rec, readKeyHTTPRequest(readKeyBody(documentID, reviewer, nil)))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status %d, want 422", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "NSDW") {
			t.Fatal("the internal container error leaked to the caller")
		}
	})

	t.Run("nothing at that url", func(t *testing.T) {
		saved := fetcher.err
		fetcher.err = errors.New("403 SignatureDoesNotMatch")
		defer func() { fetcher.err = saved }()

		rec := httptest.NewRecorder()
		srv.handleDocumentReadKey(rec, readKeyHTTPRequest(readKeyBody(documentID, reviewer, nil)))
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status %d, want 502", rec.Code)
		}
	})

	t.Run("a destroyed scope", func(t *testing.T) {
		saved := srv.engine.Materials.SeedFor
		srv.engine.Materials.SeedFor = func(string) ([]byte, error) { return nil, keyscope.ErrNoKeyMaterial }
		defer func() { srv.engine.Materials.SeedFor = saved }()

		rec := httptest.NewRecorder()
		srv.handleDocumentReadKey(rec, readKeyHTTPRequest(readKeyBody(documentID, reviewer, nil)))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status %d, want 403", rec.Code)
		}
	})

	t.Run("other methods", func(t *testing.T) {
		rec := httptest.NewRecorder()
		srv.handleDocumentReadKey(rec, httptest.NewRequest(http.MethodGet, "/v1/documents/x/read-key", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status %d, want 405", rec.Code)
		}
	})
}

func TestHandleDocumentReadKeyRouteCarriesTheDocumentID(t *testing.T) {
	srv, documentID, _, _, _ := readKeyServer(t)
	reviewer := newBrowser(t)

	// The body omits the id: it comes from the path.
	body := readKeyBody(documentID, reviewer, func(m map[string]any) { delete(m, "document_id") })

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/documents/{document_id}/read-key", srv.handleDocumentReadKey)

	req := httptest.NewRequest(http.MethodPost, "/v1/documents/"+documentID+"/read-key", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	header, _, _, err := docwire.Decode(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if header.DocumentID != documentID {
		t.Fatalf("document id = %q, want the one in the path", header.DocumentID)
	}

	t.Run("a mismatched body id is refused", func(t *testing.T) {
		mismatch := readKeyBody("someone-elses-document", reviewer, nil)
		req := httptest.NewRequest(http.MethodPost, "/v1/documents/"+documentID+"/read-key", strings.NewReader(mismatch))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", rec.Code)
		}
	})
}

func TestHandleDocumentReadKeyReceiptRecordsTheGrantWithoutTheKey(t *testing.T) {
	srv, documentID, _, _, _ := readKeyServer(t)
	reviewer := newBrowser(t)

	var seen receipt.Input
	srv.engine.Seal = func(in receipt.Input) (*receipt.SealedReceipt, error) {
		seen = in
		return &receipt.SealedReceipt{Package: receipt.Package{ReceiptID: "rcpt-read-key"}}, nil
	}

	rec := httptest.NewRecorder()
	srv.handleDocumentReadKey(rec, readKeyHTTPRequest(readKeyBody(documentID, reviewer, nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	if !strings.Contains(seen.Prompt, documentID) || !strings.Contains(seen.Prompt, "purpose=review") {
		t.Fatalf("the receipt does not name the document and the purpose: %q", seen.Prompt)
	}
	if !strings.Contains(seen.Prompt, "ttl_seconds=300") || !strings.Contains(seen.Prompt, "recipient_sha256=") {
		t.Fatalf("the receipt does not record the lifetime and the recipient: %q", seen.Prompt)
	}
	if !strings.Contains(seen.Response, "granted=true") || !strings.Contains(seen.Response, "ephemeral_sha256=") {
		t.Fatalf("the receipt does not cover what was handed over: %q", seen.Response)
	}

	// The receipt goes to a transparency log: no key material in it.
	_, grantBlob, sealedPages, err := docwire.Decode(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var grant readkey.Wrapped
	if err := json.Unmarshal(grantBlob, &grant); err != nil {
		t.Fatalf("grant: %v", err)
	}
	for _, secret := range []string{grant.SessionKey, grant.Salt, grant.Ephemeral,
		base64.StdEncoding.EncodeToString(sealedPages[0])} {
		if secret != "" && strings.Contains(seen.Prompt+seen.Response, secret) {
			t.Fatal("the receipt carries part of the grant or the page ciphertext")
		}
	}
	if seen.ChallengeNonce != testNonce() {
		t.Fatalf("receipt nonce = %q", seen.ChallengeNonce)
	}
}

func TestCanonicalReadKeyLinesAreStable(t *testing.T) {
	prompt := canonicalReadKeyPrompt("abc", "review", 2, 3, 300, "deadbeef")
	if prompt != "sealed-document/1|document.read-key|id=abc|purpose=review|key_version=2|pages=3|ttl_seconds=300|recipient_sha256=deadbeef" {
		t.Fatalf("prompt = %q", prompt)
	}
	response := canonicalReadKeyResponse("ephemeral-public-key")
	if !strings.HasPrefix(response, "sealed-document/1|document.read-key|ephemeral_sha256=") || !strings.HasSuffix(response, "|granted=true") {
		t.Fatalf("response = %q", response)
	}
}
