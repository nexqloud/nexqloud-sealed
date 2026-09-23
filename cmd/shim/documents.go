package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"nexqloud-sealed/internal/blobfetch"
	"nexqloud-sealed/internal/derive/state"
	"nexqloud-sealed/internal/documents"
	"nexqloud-sealed/internal/extract"
	"nexqloud-sealed/internal/inference"
	"nexqloud-sealed/internal/keyscope"
	"nexqloud-sealed/internal/readkey"
	"nexqloud-sealed/internal/receipt"
	"nexqloud-sealed/internal/render"
	"nexqloud-sealed/pkg/docwire"
)

// blobFetcher reads one sealed object from wherever the caller keeps it. It is an
// interface so a test can hand the handler bytes without a bucket behind them.
type blobFetcher interface {
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// textExtractor reads the text layer of a PDF inside the enclosure.
type textExtractor interface {
	Text(ctx context.Context, pdf []byte, opts render.TextOptions) (string, error)
}

// HeaderChallengeNonce carries the per-call nonce on the document endpoints. The
// chat door reads it from the JSON body; a document endpoint's body is the
// document, so the nonce travels in a header.
const HeaderChallengeNonce = "X-NexQloud-Challenge-Nonce"

// defaultMaxDocumentBytes bounds one upload. The Build Scope sizes a case at a few
// hundred documents of a couple of megabytes; this is generous for one of them and
// still a bound.
const defaultMaxDocumentBytes = 512 << 20

// handleDocumentIngest seals one uploaded document and its page renders.
//
// The body is the document itself, raw. What comes back is a container of
// ciphertext: the caller stores it wherever it likes — object storage outside the
// enclosure is the intended home — and can open none of it. Nothing about the
// document leaves this process in readable form, and no key material is returned.
func (s *server) handleDocumentIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nonce := strings.TrimSpace(r.Header.Get(HeaderChallengeNonce))
	// Optional on every sealed door: supply a nonce to bind the receipt to a
	// challenge you issued, or leave it out and the enclave generates one.
	if err := receipt.ValidateChallengeNonce(nonce); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	id, err := s.verifyIdentity(r, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	limit := s.maxDocumentBytes
	if limit <= 0 {
		limit = defaultMaxDocumentBytes
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if int64(len(body)) > limit {
		http.Error(w, fmt.Sprintf("document exceeds the %d-byte limit", limit), http.StatusRequestEntityTooLarge)
		return
	}
	if len(body) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// One derivation for every document surface: the same four inputs the chat
	// path uses, so a document and a conversation for the same customer are sealed
	// under keys derived the same way.
	dek, keyVersion, err := s.engine.DEK(id)
	if err != nil {
		if errors.Is(err, keyscope.ErrNoKeyMaterial) {
			// A scope whose wrap was destroyed is meant to be unrecoverable. This is
			// an answer, not a failure.
			http.Error(w, "no key material for this scope", http.StatusForbidden)
			return
		}
		log.Printf("document ingest: derive key: %v", err)
		http.Error(w, "key derivation failed", http.StatusInternalServerError)
		return
	}
	defer state.Zeroize(dek)

	renderer := s.renderer
	if renderer == nil {
		renderer = &render.Exec{}
	}
	pages, err := renderer.Pages(r.Context(), body, render.DefaultOptions())
	if err != nil {
		switch {
		case errors.Is(err, render.ErrNotPDF):
			http.Error(w, "body is not a PDF", http.StatusUnsupportedMediaType)
		case errors.Is(err, render.ErrNoPages):
			http.Error(w, "no pages could be rendered from this document", http.StatusUnprocessableEntity)
		default:
			log.Printf("document ingest: render: %v", err)
			http.Error(w, "rendering failed", http.StatusInternalServerError)
		}
		return
	}

	sealed, err := documents.SealDocument(dek, keyVersion, body, pages)
	if err != nil {
		log.Printf("document ingest: seal: %v", err)
		http.Error(w, "sealing failed", http.StatusInternalServerError)
		return
	}

	header := docwire.Header{
		DocumentID: sealed.Fingerprint,
		KeyVersion: sealed.KeyVersion,
	}
	pageDigests := make([]string, 0, len(sealed.Pages))
	total := len(sealed.Source)
	for _, page := range sealed.Pages {
		pageDigests = append(pageDigests, docwire.Digest(page))
		total += len(page)
	}
	header.ReceiptID, header.Receipt, header.Error = s.sealReceipt(
		id.Hash,
		nonce,
		canonicalIngestPrompt(sealed.Fingerprint, sealed.KeyVersion, len(body), len(sealed.Pages)),
		canonicalIngestResponse(docwire.Digest(sealed.Source), pageDigests, total),
		"document ingest",
	)

	w.Header().Set("Content-Type", docwire.ContentType)
	if err := docwire.Encode(w, header, sealed.Source, sealed.Pages); err != nil {
		// The status line is already on the wire, so there is nothing left to say
		// but the log.
		log.Printf("document ingest: write container: %v", err)
	}
}

// sealReceipt mints a receipt for one document operation.
//
// A receipt failure never costs the caller the work itself: the failure is recorded
// beside the result and the sealed bytes still go out, so a caller can tell that the
// proof is missing rather than assume it exists.
func (s *server) sealReceipt(claimHash, nonce, prompt, response, what string) (id string, raw json.RawMessage, errMsg string) {
	if s.engine == nil || s.engine.Seal == nil {
		return "", nil, "receipt builder not configured"
	}

	sealedReceipt, err := s.engine.Seal(receipt.Input{
		Prompt:            prompt,
		Response:          response,
		ChallengeNonce:    nonce,
		IdentityClaimHash: claimHash,
	})
	if err != nil {
		log.Printf("%s: receipt: %v", what, err)
		return "", nil, "receipt build failed"
	}

	if encoded, err := json.Marshal(sealedReceipt); err == nil {
		raw = encoded
	} else {
		log.Printf("%s: encode receipt: %v", what, err)
	}
	s.publishReceipt(sealedReceipt)
	return sealedReceipt.Package.ReceiptID, raw, ""
}

// canonicalIngestPrompt is what the receipt's prompt_hash covers: which document,
// under which key version. The document's plaintext fingerprint is in there, so a
// receipt names the document rather than a prompt string.
func canonicalIngestPrompt(documentID string, keyVersion, sourceBytes, pages int) string {
	return fmt.Sprintf("sealed-document/1|document.ingest|id=%s|key_version=%d|source_bytes=%d|pages=%d",
		documentID, keyVersion, sourceBytes, pages)
}

// readKeyRequest is a reviewer's browser asking to see one document.
//
// The document is not in the request and the key it asks for is not addressed to
// the caller: recipient_public_key is the browser's own public key, generated for
// this review session and never shared. The application relaying this request is
// not the party being handed access — that is the whole point.
type readKeyRequest struct {
	DocumentID         string `json:"document_id"`
	Purpose            string `json:"purpose"`
	TTLSeconds         int    `json:"ttl_seconds"`
	RecipientPublicKey string `json:"recipient_public_key"`
	SourceURL          string `json:"source_url"`
	ChallengeNonce     string `json:"challenge_nonce,omitempty"`
}

// handleDocumentReadKey issues a short-lived key that opens one document's page
// renders, addressed to the browser that asked for it.
//
// The response is a container of ciphertext, not JSON: the first part is the grant
// (the session key wrapped to the recipient, with its expiry) and the rest are the
// page renders re-sealed under that session key. The calling application can hold
// and relay the whole thing without being able to read a page.
func (s *server) handleDocumentReadKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxExtractRequestBytes))
	if err != nil {
		http.Error(w, "cannot read request", http.StatusBadRequest)
		return
	}
	var req readKeyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "request is not json", http.StatusBadRequest)
		return
	}
	if err := receipt.ValidateChallengeNonce(req.ChallengeNonce); err != nil {
		http.Error(w, "challenge nonce is not acceptable", http.StatusBadRequest)
		return
	}
	id, err := s.verifyIdentity(r, "")
	if err != nil {
		http.Error(w, "identity is not acceptable", http.StatusUnauthorized)
		return
	}

	documentID := strings.TrimSpace(r.PathValue("document_id"))
	if documentID == "" {
		documentID = strings.TrimSpace(req.DocumentID)
	} else if req.DocumentID != "" && req.DocumentID != documentID {
		http.Error(w, "document id in the path and the body disagree", http.StatusBadRequest)
		return
	}
	if documentID == "" {
		http.Error(w, "no document named", http.StatusBadRequest)
		return
	}

	// One purpose exists today, so an unstated one means review; anything else is
	// refused rather than quietly treated as a read of the pages.
	purpose := strings.TrimSpace(req.Purpose)
	if purpose == "" {
		purpose = readkey.PurposeReview
	}
	if purpose != readkey.PurposeReview {
		http.Error(w, fmt.Sprintf("purpose %q is not issuable", purpose), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.SourceURL) == "" {
		http.Error(w, "source_url is required", http.StatusBadRequest)
		return
	}
	// Refuse an unusable recipient now: a grant nobody can open is worse than an
	// error, because it looks like access was given.
	recipient, err := readkey.ParseRecipient(strings.TrimSpace(req.RecipientPublicKey))
	if err != nil {
		http.Error(w, "recipient_public_key is not a usable public key", http.StatusBadRequest)
		return
	}

	dek, keyVersion, err := s.engine.DEK(id)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, keyscope.ErrNoKeyMaterial) {
			status = http.StatusForbidden
		}
		log.Printf("document read-key: derive key: %v", err)
		http.Error(w, "no key material for this scope", status)
		return
	}

	fetch := s.fetcher
	if fetch == nil {
		fetch = &blobfetch.Fetcher{}
	}
	container, err := fetch.Fetch(r.Context(), strings.TrimSpace(req.SourceURL))
	if err != nil {
		log.Printf("document read-key: fetch: %v", err)
		http.Error(w, "cannot read the sealed document", http.StatusBadGateway)
		return
	}
	header, _, sealedPages, err := docwire.Decode(bytes.NewReader(container))
	if err != nil {
		log.Printf("document read-key: container: %v", err)
		http.Error(w, "stored bytes are not a sealed document", http.StatusUnprocessableEntity)
		return
	}
	if header.KeyVersion != keyVersion {
		http.Error(w, fmt.Sprintf("document is sealed under key version %d", header.KeyVersion), http.StatusUnprocessableEntity)
		return
	}
	if header.DocumentID != "" && header.DocumentID != documentID {
		http.Error(w, "that container holds a different document", http.StatusUnprocessableEntity)
		return
	}
	if len(sealedPages) == 0 {
		http.Error(w, "the document has no page renders to read", http.StatusUnprocessableEntity)
		return
	}

	// Open the renders this enclave is permitted to show, then re-seal each under
	// the session key so the browser can read it and the caller cannot.
	pages := make([][]byte, 0, len(sealedPages))
	for i, sealed := range sealedPages {
		kind, page, err := documents.Open(dek, sealed, keyVersion)
		if err != nil {
			log.Printf("document read-key: open page %d: %v", i+1, err)
			http.Error(w, "the sealed pages cannot be opened with this key", http.StatusUnprocessableEntity)
			return
		}
		if kind != documents.KindPage {
			log.Printf("document read-key: page %d is a %s", i+1, kind)
			http.Error(w, "that container holds something other than page renders", http.StatusUnprocessableEntity)
			return
		}
		pages = append(pages, page)
	}

	grant, err := readkey.Issue(recipient, documentID, purpose, keyVersion, len(pages), readkey.ClampTTL(req.TTLSeconds), time.Now())
	if err != nil {
		log.Printf("document read-key: issue: %v", err)
		http.Error(w, "cannot issue a read key", http.StatusInternalServerError)
		return
	}

	resealed := make([][]byte, 0, len(pages))
	for i, page := range pages {
		blob, err := readkey.SealPage(grant.Key, page)
		if err != nil {
			log.Printf("document read-key: seal page %d: %v", i+1, err)
			http.Error(w, "cannot prepare the pages for the recipient", http.StatusInternalServerError)
			return
		}
		resealed = append(resealed, blob)
	}

	// The grant travels as the container's first part: public by construction, and
	// the only thing the recipient's browser needs besides the page bytes.
	grantJSON, err := json.Marshal(grant.Wrapped)
	if err != nil {
		log.Printf("document read-key: grant json: %v", err)
		http.Error(w, "cannot describe the grant", http.StatusInternalServerError)
		return
	}

	out := docwire.Header{
		DocumentID:   documentID,
		KeyVersion:   keyVersion,
		DetectedType: "read-key-grant",
	}
	promptLine := canonicalReadKeyPrompt(documentID, purpose, keyVersion, len(pages), grant.Wrapped.TTLSeconds, grant.Wrapped.RecipientSHA256)
	responseLine := canonicalReadKeyResponse(grant.Wrapped.Ephemeral)
	out.ReceiptID, out.Receipt, out.Error = s.sealReceipt(id.Hash, req.ChallengeNonce, promptLine, responseLine, "document read-key")

	w.Header().Set("Content-Type", docwire.ContentType)
	w.WriteHeader(http.StatusOK)
	if err := docwire.Encode(w, out, grantJSON, resealed); err != nil {
		// The status line is already out; the caller sees a truncated container and
		// docwire refuses it, which is the honest outcome here.
		log.Printf("document read-key: encode: %v", err)
	}
}

func canonicalReadKeyPrompt(documentID, purpose string, keyVersion, pages, ttlSeconds int, recipientSHA string) string {
	return fmt.Sprintf("sealed-document/1|document.read-key|id=%s|purpose=%s|key_version=%d|pages=%d|ttl_seconds=%d|recipient_sha256=%s",
		documentID, purpose, keyVersion, pages, ttlSeconds, recipientSHA)
}

// canonicalReadKeyResponse covers what was handed over. It names the ephemeral
// public key by digest and never the wrapped session key: a receipt is published
// to a transparency log, and the wrapped key is addressed to one browser.
func canonicalReadKeyResponse(ephemeral string) string {
	return fmt.Sprintf("sealed-document/1|document.read-key|ephemeral_sha256=%s|granted=true",
		docwire.Digest([]byte(ephemeral)))
}

// canonicalExtractPrompt is what response_hash covers: the sealed bytes actually
// handed back, part by part.
func canonicalIngestResponse(sourceDigest string, pageDigests []string, sealedBytes int) string {
	return fmt.Sprintf("sealed-document/1|document.ingest|source_sha256=%s|pages=%s|sealed_bytes=%d",
		sourceDigest, strings.Join(pageDigests, ","), sealedBytes)
}

// ExtractInput is the caller's ask on the extraction door.
type ExtractInput struct {
	SchemaID   string
	Schema     json.RawMessage
	DocumentID string
	KeyVersion int
	SourceURL  string
	Model      string
}

type extractRequest struct {
	SchemaID       string          `json:"schema_id"`
	Schema         json.RawMessage `json:"schema"`
	DocumentID     string          `json:"document_id"`
	KeyVersion     int             `json:"key_version"`
	SourceURL      string          `json:"source_url"`
	Model          string          `json:"model,omitempty"`
	ChallengeNonce string          `json:"challenge_nonce,omitempty"`
}

type extractResponse struct {
	DocumentID string         `json:"document_id"`
	SchemaID   string         `json:"schema_id"`
	Model      string         `json:"model,omitempty"`
	Fields     map[string]any `json:"fields"`
	// RawAnswer is the model's own answer, before parsing, and AnswerSHA256 is its
	// digest as the receipt records it. A caller checks the digest and reads the
	// fields out of this rather than trusting the parsed copy: otherwise a field
	// could be altered in transit while the receipt still verified.
	RawAnswer    string `json:"raw_answer,omitempty"`
	AnswerSHA256 string `json:"answer_sha256,omitempty"`
	// Confidence is measured from the engine's token probabilities. Absent means the
	// engine reported none — never that the fields are certain.
	Confidence       map[string]float64 `json:"confidence,omitempty"`
	ConfidenceSource string             `json:"confidence_source"`
	// ModelConfidence is what the model claimed about itself, kept beside the
	// measured figure rather than in place of it.
	ModelConfidence map[string]float64 `json:"model_confidence,omitempty"`
	Pages           int                `json:"pages"`
	// ReadFrom says what the read was made of: the document's text layer, or its pages as
	// pictures. A caller that shows a person what was read needs to know which it was.
	ReadFrom      string          `json:"read_from,omitempty"`
	ReceiptID     string          `json:"receipt_id,omitempty"`
	SealedReceipt json.RawMessage `json:"sealed_receipt,omitempty"`
	ReceiptError  string          `json:"receipt_error,omitempty"`
	// ReceiptPrompt and ReceiptResponse are the exact canonical lines the receipt's
	// prompt_hash and response_hash cover. Returning them is what makes a receipt
	// checkable by any caller in any language without reimplementing this enclave's
	// canonical form: the caller hashes the line it was given and reads the values
	// out of it, then checks they describe what it asked for.
	ReceiptPrompt   string `json:"receipt_prompt,omitempty"`
	ReceiptResponse string `json:"receipt_response,omitempty"`
}

// maxExtractTokens bounds one extraction answer. Twelve fields of JSON is nothing;
// this is the stop for a model that starts writing an essay instead.
const maxExtractTokens = 2048

// unwrapContainer returns the sealed source envelope from whatever a caller stored.
//
// A caller keeps one sealed object per document: the container the ingest door handed
// back. That container is transport for three things — the source envelope, the page
// renders, and the header that names both — so a door that wants the source should take
// it out of the container rather than make every caller learn the format. Bytes that are
// not a container are passed through, because a caller who kept only the envelope is
// still a caller.
//
// Decoding verifies every part against its digest, so a container that changed on the
// way here is refused as corrupted — never opened and reported as the wrong key.
func unwrapContainer(blob []byte, documentID string, keyVersion int) ([]byte, error) {
	header, source, _, err := docwire.Decode(bytes.NewReader(blob))
	if err != nil {
		if errors.Is(err, docwire.ErrNotDocwire) {
			return blob, nil
		}
		return nil, fmt.Errorf("the stored container is damaged: %v", err)
	}
	if header.KeyVersion != keyVersion {
		return nil, fmt.Errorf("the container is sealed under key version %d", header.KeyVersion)
	}
	if header.DocumentID != "" && documentID != "" && header.DocumentID != documentID {
		return nil, errors.New("that container holds a different document")
	}
	if len(source) == 0 {
		return nil, errors.New("the container holds no document source")
	}
	return source, nil
}

// handleDocumentExtract reads one sealed document and returns the fields printed
// on it.
//
// The document arrives as a reference to its ciphertext, not as bytes: the enclave
// fetches the object itself, so a large case never travels through the calling
// application. The plaintext exists only inside this process, for the length of one
// read, and none of it is returned.
func (s *server) handleDocumentExtract(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxExtractRequestBytes))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var req extractRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Optional on every sealed door: supply a nonce to bind the receipt to a
	// challenge you issued, or leave it out and the enclave generates one.
	if err := receipt.ValidateChallengeNonce(strings.TrimSpace(req.ChallengeNonce)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	id, err := s.verifyIdentity(r, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	documentID := strings.TrimSpace(r.PathValue("document_id"))
	if documentID == "" {
		documentID = strings.TrimSpace(req.DocumentID)
	}
	if documentID == "" {
		http.Error(w, "document_id is required", http.StatusBadRequest)
		return
	}
	if req.DocumentID != "" && documentID != strings.TrimSpace(req.DocumentID) {
		http.Error(w, "document_id does not match the path", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.SchemaID) == "" {
		http.Error(w, "schema_id is required", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.SourceURL) == "" {
		http.Error(w, "source_url is required", http.StatusBadRequest)
		return
	}
	if req.KeyVersion <= 0 {
		http.Error(w, "key_version is required", http.StatusBadRequest)
		return
	}

	fields, err := extract.Fields(req.Schema)
	if err != nil {
		http.Error(w, "schema cannot describe an extraction", http.StatusBadRequest)
		return
	}

	dek, keyVersion, err := s.engine.DEK(id)
	if err != nil {
		if errors.Is(err, keyscope.ErrNoKeyMaterial) {
			http.Error(w, "no key material for this scope", http.StatusForbidden)
			return
		}
		log.Printf("document extract: derive key: %v", err)
		http.Error(w, "key derivation failed", http.StatusInternalServerError)
		return
	}
	defer state.Zeroize(dek)

	if keyVersion != req.KeyVersion {
		// The envelope records the version it was sealed under; asking for a
		// different one means the caller is holding a document this key cannot open.
		http.Error(w, fmt.Sprintf("document is sealed under key version %d", keyVersion), http.StatusUnprocessableEntity)
		return
	}

	sealed, err := s.fetchSealed(r.Context(), req.SourceURL)
	if err != nil {
		log.Printf("document extract: fetch: %v", err)
		http.Error(w, "could not read the sealed document", http.StatusBadGateway)
		return
	}

	// What a caller holds is what the ingest door handed them: a sealed-document
	// container, with the source envelope inside it. Accepting our own container back is
	// the difference between one sealed object per document and a caller that has to
	// know which part of it this door happens to want — and the container's own header
	// is a better check than the caller's word, so it is checked here too.
	sealed, err = unwrapContainer(sealed, documentID, keyVersion)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	kind, plaintext, err := documents.Open(dek, sealed, keyVersion)
	if err != nil {
		log.Printf("document extract: open: %v", err)
		http.Error(w, "the sealed document could not be opened with this key", http.StatusUnprocessableEntity)
		return
	}
	if kind != documents.KindSource {
		http.Error(w, "that object is not a document source", http.StatusUnprocessableEntity)
		return
	}

	textExtractor := s.text
	if textExtractor == nil {
		textExtractor = &render.ExecText{}
	}
	text, err := textExtractor.Text(r.Context(), plaintext, render.TextDefaults())

	// No text layer means a scan: a picture of a form. There is nothing to quote, so the pages
	// themselves are read — the same question, the same schema, the same measurement, asked of
	// pictures instead of characters. What the read was made from travels in the receipt, because
	// a text read and a picture read of the same document are different evidence.
	readFrom := readFromText
	var (
		images     []inference.Image
		imagePages []extract.PageImage
	)
	if err != nil {
		if !errors.Is(err, render.ErrNoText) {
			switch {
			case errors.Is(err, render.ErrNotPDF):
				http.Error(w, "that object is not a PDF", http.StatusUnprocessableEntity)
			default:
				log.Printf("document extract: text: %v", err)
				http.Error(w, "reading the document failed", http.StatusInternalServerError)
			}
			return
		}

		rendered, renderErr := s.pageImages(r.Context(), plaintext)
		if renderErr != nil {
			switch {
			case errors.Is(renderErr, errTooManyPages):
				// The whole document, or none of it: a person gets this one.
				http.Error(w, renderErr.Error(), http.StatusUnprocessableEntity)
			case errors.Is(renderErr, render.ErrNoPages):
				http.Error(w, "no pages could be rendered from this document", http.StatusUnprocessableEntity)
			default:
				log.Printf("document extract: render: %v", renderErr)
				http.Error(w, "rendering the pages failed", http.StatusInternalServerError)
			}
			return
		}
		for i, page := range rendered {
			digest := docwire.Digest(page)
			log.Printf("[sealed] read:   page %d/%d → image %s (%d KiB)",
				i+1, len(rendered), digest[:12], len(page)>>10)
			imagePages = append(imagePages, extract.PageImage{
				Number:   i + 1,
				SHA256:   digest,
				MIMEType: "image/png",
				Bytes:    len(page),
			})
			images = append(images, inference.Image{MIMEType: "image/png", Data: page})
		}
		log.Printf("[sealed] read: %s has no text layer — the read is made from %d page image(s) at %d DPI, not from text",
			documentID, len(rendered), readDPIFromEnv())
		readFrom = readFromPageImages
	} else {
		log.Printf("[sealed] read: %s read from its text layer (%d characters)",
			documentID, len(text))
	}

	var prompt string
	if readFrom == readFromPageImages {
		prompt, err = extract.BuildImagePrompt(req.Schema, imagePages)
	} else {
		prompt, err = extract.BuildPrompt(req.Schema, text)
	}
	if err != nil {
		http.Error(w, "schema cannot describe an extraction", http.StatusBadRequest)
		return
	}

	// The engine is constrained to the answer's *shape*, not to the caller's value
	// formatting: used directly as a grammar, a caller's schema coerces what the page
	// prints and lets the engine stop after one field. See extract.EnvelopeSchema.
	constraint, err := extract.EnvelopeSchema(req.Schema)
	if err != nil {
		http.Error(w, "schema cannot describe an extraction", http.StatusBadRequest)
		return
	}

	temperature := 0.0
	maxTokens := maxExtractTokens
	if s.engine.Inference == nil {
		log.Printf("document extract: no inference backend configured")
		http.Error(w, "no inference backend configured", http.StatusServiceUnavailable)
		return
	}
	log.Printf("[sealed] read: asking the engine read=%s images=%d prompt=%d chars model=%s",
		readFrom, len(images), len(prompt), strings.TrimSpace(req.Model))
	completion, err := s.engine.Inference.Complete(inference.Request{
		Model:          strings.TrimSpace(req.Model),
		Prompt:         prompt,
		Images:         images,
		Temperature:    &temperature,
		MaxTokens:      &maxTokens,
		JSONSchema:     string(constraint),
		Logprobs:       true,
		TopLogprobs:    extractTopLogprobs,
		TenantID:       id.TenantID,
		ChallengeNonce: strings.TrimSpace(req.ChallengeNonce),
		// A read is an answer to a question, not a deliberation: reasoning spends the
		// token budget and leaves no content to read.
		DisableThinking: true,
	})
	if err != nil {
		log.Printf("document extract: inference: %v", err)
		http.Error(w, "reading the document failed", http.StatusBadGateway)
		return
	}

	answer, err := extract.Parse(completion.Content)
	if err != nil {
		log.Printf("document extract: parse: %v", err)
		http.Error(w, "the model did not return a usable record", http.StatusUnprocessableEntity)
		return
	}

	measured := extract.Confidence(completion.Content, completion.TokenLogprobs, fields)
	source := "none"
	if measured != nil {
		source = "logprobs"
	}

	// How many pages the read actually covered: the pages with text, or the pages that were
	// drawn and shown to the model.
	pagesRead := len(render.PageTexts(text))
	if readFrom == readFromPageImages {
		pagesRead = len(images)
	}

	out := extractResponse{
		DocumentID:       documentID,
		SchemaID:         strings.TrimSpace(req.SchemaID),
		Model:            completion.Model,
		Fields:           answer.Fields,
		Confidence:       measured,
		ConfidenceSource: source,
		ModelConfidence:  answer.Confidence,
		Pages:            pagesRead,
		ReadFrom:         readFrom,
		RawAnswer:        completion.Content,
		AnswerSHA256:     docwire.Digest([]byte(completion.Content)),
	}

	promptLine := canonicalExtractPrompt(documentID, out.SchemaID, out.ReadFrom, keyVersion, out.Pages)
	responseLine := canonicalExtractResponse(completion.Model, completion.Content, measured)
	out.ReceiptPrompt = promptLine
	out.ReceiptResponse = responseLine
	out.ReceiptID, out.SealedReceipt, out.ReceiptError = s.sealReceipt(id.Hash, req.ChallengeNonce, promptLine, responseLine, "document extract")

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		log.Printf("document extract: write response: %v", err)
	}
}

// extractTopLogprobs asks the engine for a few alternatives per token. One would
// be enough for the measured value; the extras make a review screen able to show
// what the model nearly said instead.
const extractTopLogprobs = 3

// What a read was made from, as the receipt records it.
const (
	// readFromText is the document's own text layer, quoted into the prompt.
	readFromText = "text"
	// readFromPageImages is the document's pages, drawn and attached as pictures: a scan.
	readFromPageImages = "page_images"
)

// maxPageImageRead bounds how many pages a picture read covers.
//
// Pictures cost input tokens in a way text does not, and the guest's context is finite. Rather
// than quietly reading the first few pages of a bundle and reporting it as the document, a
// document over the bound is refused and goes to a person: half a document read as pictures,
// with nothing saying so, is worse than an honest refusal.
const maxPageImageRead = 8

// readDPI is how finely a page is drawn for a picture read.
//
// Rendering finer than about 200 DPI buys nothing: the vision encoder resizes whatever it is given
// to a fixed token budget, so extra pixels are thrown away before the model ever sees them.
// Measured on this deployment against the served model —
//
//	200 DPI  1700x2200 ( 3.7 Mpx)  ->  3676 prompt tokens
//	400 DPI  3400x4400 (15.0 Mpx)  ->  4051 prompt tokens
//	600 DPI  5100x6600 (33.7 Mpx)  ->  4051 prompt tokens   (the cap)
//
// — i.e. one image is capped near 4,000 tokens (~3.2 Mpx), and a page rendered at 400 DPI is
// therefore *downscaled* to that budget, which is slightly worse than 200 DPI rather than better.
//
// What that means for reading small print: a whole 200 DPI letter page spends about 1,000 pixels
// per token, so an eight-point figure in a 7501's line grid (about 22 px tall) falls inside a
// single token and cannot be read at all — which is why a scan read returned the large header
// fields and null for every grid field, while the same form's text layer read them at 0.99
// confidence. Raising the DPI cannot fix that. Giving the *region* its own image can: the same
// 4,000-token budget spent on the grid instead of the whole page resolves about four times finer.
// That is a change of what is attached, not of how it is rendered.
//
// SEALED_READ_DPI overrides the render; SEALED_READ_PAGE_LIMIT overrides the page bound. The page
// bound belongs with the engine's context: one page costs about 3,700 prompt tokens at 200 DPI.
const readDPI = 200

// readDPIFromEnv is the render resolution a picture read uses.
func readDPIFromEnv() int {
	if value := strings.TrimSpace(os.Getenv("SEALED_READ_DPI")); value != "" {
		if dpi, err := strconv.Atoi(value); err == nil && dpi > 0 {
			return dpi
		}
	}
	return readDPI
}

// readPageLimitFromEnv is how many pages one picture read covers.
func readPageLimitFromEnv() int {
	if value := strings.TrimSpace(os.Getenv("SEALED_READ_PAGE_LIMIT")); value != "" {
		if limit, err := strconv.Atoi(value); err == nil && limit > 0 {
			return limit
		}
	}
	return maxPageImageRead
}

// errTooManyPages means the document has more pages than a picture read covers. The body says so,
// with both numbers, so a caller can act on it instead of guessing at a rendering failure.
var errTooManyPages = errors.New("too many pages to read as pictures")

// pageImages draws the pages of a document inside the enclosure.
func (s *server) pageImages(ctx context.Context, pdf []byte) ([][]byte, error) {
	renderer := s.renderer
	if renderer == nil {
		renderer = &render.Exec{}
	}
	limit := readPageLimitFromEnv()
	opts := render.DefaultOptions()
	opts.DPI = readDPIFromEnv()
	// One more than the bound, so "too long" can be told apart from "exactly at the bound".
	opts.MaxPages = limit + 1
	pages, err := renderer.Pages(ctx, pdf, opts)
	if err != nil {
		return nil, err
	}
	if len(pages) > limit {
		return nil, fmt.Errorf("%w: %d pages, this deployment reads up to %d as pictures",
			errTooManyPages, len(pages), limit)
	}
	return pages, nil
}

// maxExtractRequestBytes bounds the extraction request. The document is not in it —
// only a URL and a schema — so this is generous.
const maxExtractRequestBytes = 1 << 20

func (s *server) fetchSealed(ctx context.Context, url string) ([]byte, error) {
	fetcher := s.fetcher
	if fetcher == nil {
		fetcher = &blobfetch.Fetcher{}
	}
	return fetcher.Fetch(ctx, url)
}

// canonicalExtractPrompt is what prompt_hash covers: the document, the schema it was read
// against, how it was read, and how many pages that covered.
//
// The read mode is in the line because it changes what the evidence is. A form whose text layer
// was quoted and a scan whose pages were looked at are not the same read, even for the same
// document and schema, and a receipt that could not tell them apart would let either pass for the
// other.
func canonicalExtractPrompt(documentID, schemaID, readFrom string, keyVersion, pages int) string {
	return fmt.Sprintf("sealed-document/1|document.extract|id=%s|schema=%s|read=%s|key_version=%d|pages=%d",
		documentID, schemaID, readFrom, keyVersion, pages)
}

// canonicalExtractResponse is what response_hash covers: which model read the
// document, and what it answered.
//
// Every value in this line is a string either side of the boundary can reproduce
// byte for byte: the answer by digest, the confidences fixed to four decimals.
// Floating-point JSON is deliberately absent — Go writes a whole number as `1` and
// Python as `1.0`, so binding a re-marshalled map would hand the caller a receipt it
// cannot verify, which is worse than one without the number. The caller gets the
// answer itself in the response, so it can hash exactly what it was given.
func canonicalExtractResponse(model, answer string, confidence map[string]float64) string {
	return fmt.Sprintf("sealed-document/1|document.extract|model=%s|answer_sha256=%s|confidence=%s",
		model, docwire.Digest([]byte(answer)), canonicalConfidence(confidence))
}

// canonicalConfidence renders the measured confidences in one language-neutral
// form: keys sorted, four decimal places, no spaces. `none` means the engine
// reported no token probabilities and nothing was measured.
func canonicalConfidence(confidence map[string]float64) string {
	if len(confidence) == 0 {
		return "none"
	}
	names := make([]string, 0, len(confidence))
	for name := range confidence {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%q:%.4f", name, confidence[name]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}
