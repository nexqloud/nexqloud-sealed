package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"nexqloud-sealed/internal/chat"
	"nexqloud-sealed/internal/chatstate"
	"nexqloud-sealed/internal/derive/material"
	"nexqloud-sealed/internal/devmode"
	"nexqloud-sealed/internal/enclave"
	"nexqloud-sealed/internal/identity"
	"nexqloud-sealed/internal/inference"
	"nexqloud-sealed/internal/receipt"
)

const defaultAddr = ":8080"

type server struct {
	engine      *chat.Engine
	jwksURL     string
	tenantID    string
	ledgerURL   string
	endpointKey string
	verifyMode  string
	httpClient  *http.Client
	ready       atomic.Bool
}

func main() {
	jwksURL := flag.String("jwks", strings.TrimSpace(os.Getenv("NEXQLOUD_JWKS_URL")), "customer IdP JWKS URL for X-NexQloud-Identity")
	tenantID := flag.String("tenant", strings.TrimSpace(os.Getenv("NEXQLOUD_TENANT_ID")), "optional tenant_id to require in identity JWT")
	dev := flag.Bool("dev", devmode.Enabled(), "allow dev fallbacks (or set NEXQLOUD_DEV=1)")
	addr := flag.String("addr", envOr("NEXQLOUD_SHIM_ADDR", defaultAddr), "listen address")
	flag.Parse()

	if *dev {
		_ = os.Setenv("NEXQLOUD_DEV", "1")
	}

	srv := &server{
		jwksURL:     strings.TrimSpace(*jwksURL),
		tenantID:    strings.TrimSpace(*tenantID),
		ledgerURL:   strings.TrimSpace(os.Getenv("NEXQLOUD_LEDGER_URL")),
		endpointKey: strings.TrimSpace(os.Getenv("NEXQLOUD_ENDPOINT_KEY")),
		verifyMode:  strings.TrimSpace(os.Getenv("NEXQLOUD_VERIFY_MODE")),
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
	if srv.verifyMode == "" {
		srv.verifyMode = "per-response"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", srv.handleHealth)
	mux.HandleFunc("/v1/chat/completions", srv.requireReady(srv.handleChatCompletions))
	mux.HandleFunc("/v1/chat/decrypt", srv.requireReady(srv.handleDecrypt))

	go func() {
		log.Printf("sealed-shim listening on %s (health ready; attestation warmup continuing)", *addr)
		log.Fatal(http.ListenAndServe(*addr, mux))
	}()

	priv, pub, err := enclave.Key()
	if err != nil {
		log.Fatalf("generate enclave key: %v", err)
	}

	log.Printf("warming AMD KDS certificate cache (VCEK, ASK, ARK)...")
	if err := enclave.WarmCertificateCache(pub); err != nil {
		log.Fatalf("warm certificate cache: %v", err)
	}
	log.Printf("AMD certificate cache ready")

	seed, err := material.Seed()
	if err != nil {
		log.Fatalf("operator seed: %v", err)
	}
	chip, err := material.Chip()
	if err != nil {
		log.Fatalf("chip secret: %v", err)
	}
	attestBind := loadAttestBind(pub)

	receiptBuilder := receipt.NewBuilder(priv, pub)
	srv.engine = &chat.Engine{
		Inference: selectInferenceBackend(),
		Seal:      receiptBuilder.Seal,
		Materials: chat.Materials{
			Seed:       seed,
			Chip:       chip,
			AttestBind: attestBind,
			KeyVersion: material.KeyVersion,
		},
	}

	if srv.jwksURL == "" {
		if !devmode.Enabled() {
			log.Fatal("NEXQLOUD_JWKS_URL (or -jwks) is required in production")
		}
		log.Printf("identity: dev mode — %s optional, receipts may use placeholder identity_claim_hash", identity.HeaderNexQloudIdentity)
	} else {
		log.Printf("identity: verifying %s against JWKS %s", identity.HeaderNexQloudIdentity, srv.jwksURL)
		if srv.tenantID != "" {
			log.Printf("identity: requiring tenant_id/sub=%q", srv.tenantID)
		}
	}

	srv.ready.Store(true)
	log.Printf("sealed-shim ready (inference=%T, dev=%v, ledger=%v, mode=%s)", srv.engine.Inference, devmode.Enabled(), srv.ledgerURL != "", srv.verifyMode)
	select {}
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func selectInferenceBackend() inference.Backend {
	if url := os.Getenv("VLLM_URL"); url != "" {
		log.Printf("inference backend: vLLM at %s", url)
		return inference.NewVLLM(url)
	}
	if !devmode.Enabled() {
		log.Fatal("VLLM_URL is required in production (or set NEXQLOUD_DEV=1 for mock inference)")
	}
	log.Printf("inference backend: mock (set VLLM_URL to use real vLLM)")
	return inference.NewMock()
}

func loadAttestBind(pub ed25519.PublicKey) []byte {
	if devmode.Enabled() {
		return material.DevAttestBind()
	}
	nonce := make([]byte, 32)
	att, err := enclave.RequestReport(pub, nonce)
	if err != nil {
		log.Fatalf("attest bind measurement: %v", err)
	}
	if att == nil || att.Report == nil || len(att.Report.Measurement) == 0 {
		log.Fatal("attest bind measurement missing")
	}
	return material.AttestBindFromMeasurement(att.Report.Measurement)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	status := "starting"
	if s.ready.Load() {
		status = "ok"
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
}

func (s *server) requireReady(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.ready.Load() {
			http.Error(w, "sealed-shim still starting", http.StatusServiceUnavailable)
			return
		}
		next(w, r)
	}
}

func (s *server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var req inference.Request
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if err := receipt.ValidateChallengeNonce(req.ChallengeNonce); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	id, err := s.verifyIdentity(r, req.JWTToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if req.Stream {
		s.streamTurn(w, id, req)
		return
	}

	out, err := s.engine.Turn(id, req, nil)
	if err != nil {
		if out.Content == "" && out.EncryptedPayload == "" {
			s.writeTurnError(w, err)
			return
		}
		log.Printf("turn failed: %v", err)
	}

	resp := completionJSON(out)
	if err != nil {
		resp["receipt_error"] = err.Error()
	}
	s.publishReceipt(out.Receipt)

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(resp); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func (s *server) streamTurn(w http.ResponseWriter, id identity.VerifiedIdentity, req inference.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	out, err := s.engine.Turn(id, req, func(token string) error {
		return writeSSE(w, flusher, "token", map[string]string{"content": token})
	})
	if err != nil {
		log.Printf("turn failed: %v", err)
		if out.Content == "" && out.EncryptedPayload == "" {
			_ = writeSSE(w, flusher, "error", map[string]string{
				"error":  publicTurnError(err),
				"detail": err.Error(),
			})
			return
		}
	}

	s.publishReceipt(out.Receipt)
	payload := completionJSON(out)
	if err != nil {
		payload["receipt_error"] = err.Error()
	}
	if err := writeSSE(w, flusher, "sealed", payload); err != nil {
		log.Printf("sse sealed: %v", err)
	}
}

func (s *server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req struct {
		EncryptedPayload string `json:"encrypted_payload"`
		JWTToken         string `json:"jwt_token"`
		TenantID         string `json:"tenant_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	id, err := s.verifyIdentity(r, req.JWTToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	msgs, err := s.engine.Decrypt(id, req.EncryptedPayload)
	if err != nil {
		s.writeTurnError(w, err)
		return
	}
	if msgs == nil {
		msgs = []chatstate.Message{}
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(map[string]any{"messages": msgs})
}

func completionJSON(out chat.TurnResult) map[string]any {
	model := out.Model
	return map[string]any{
		"id":                "chatcmpl-" + uuid.NewString(),
		"object":            "chat.completion",
		"created":           time.Now().Unix(),
		"model":             model,
		"encrypted_payload": out.EncryptedPayload,
		"receipt_id":        out.ReceiptID,
		"sealed_receipt":    out.Receipt,
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": out.Content,
				},
				"finish_reason": "stop",
			},
		},
	}
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, event string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, raw); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

func (s *server) writeTurnError(w http.ResponseWriter, err error) {
	if chat.IsInvalidPayload(err) {
		http.Error(w, "invalid encrypted_payload", http.StatusBadRequest)
		return
	}
	if strings.Contains(err.Error(), "missing prompt") {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("turn failed: %v", err)
	if strings.Contains(err.Error(), "inference") {
		http.Error(w, "inference failed", http.StatusBadGateway)
		return
	}
	if strings.Contains(err.Error(), "receipt") {
		http.Error(w, "receipt build failed", http.StatusInternalServerError)
		return
	}
	http.Error(w, "turn failed", http.StatusInternalServerError)
}

func publicTurnError(err error) string {
	if err == nil {
		return "turn failed"
	}
	if chat.IsInvalidPayload(err) {
		return "invalid encrypted_payload"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "missing prompt"):
		return msg
	case strings.Contains(msg, "inference"), strings.Contains(msg, "vllm"):
		return "inference failed"
	case strings.Contains(msg, "receipt"), strings.Contains(msg, "attestation"), strings.Contains(msg, "wipe"), strings.Contains(msg, "model-attest"):
		return "receipt build failed"
	default:
		return "turn failed"
	}
}

func (s *server) publishReceipt(sealedReceipt any) {
	if sealedReceipt == nil || s.ledgerURL == "" || s.verifyMode != "per-response" {
		return
	}
	endpointKey := s.endpointKey
	if endpointKey == "" {
		log.Printf("ledger: skip publish (NEXQLOUD_ENDPOINT_KEY empty)")
		return
	}
	go func() {
		body, err := json.Marshal(map[string]any{
			"endpointKey": endpointKey,
			"receipt":     sealedReceipt,
		})
		if err != nil {
			log.Printf("ledger: marshal failed: %v", err)
			return
		}
		req, err := http.NewRequest(http.MethodPost, s.ledgerURL, strings.NewReader(string(body)))
		if err != nil {
			log.Printf("ledger: build request failed: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.httpClient.Do(req)
		if err != nil {
			log.Printf("ledger: publish failed: %v", err)
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode >= 300 {
			log.Printf("ledger: publish status %d", resp.StatusCode)
			return
		}
		log.Printf("ledger: published receipt for endpoint %s", endpointKey)
	}()
}

func (s *server) verifyIdentity(r *http.Request, bodyToken string) (identity.VerifiedIdentity, error) {
	token := strings.TrimSpace(r.Header.Get(identity.HeaderNexQloudIdentity))
	if token == "" {
		token = strings.TrimSpace(bodyToken)
	}
	if s.jwksURL == "" {
		if token != "" {
			log.Printf("identity: ignoring token (JWKS not configured)")
		}
		if !devmode.Enabled() {
			return identity.VerifiedIdentity{}, errIdentity("JWKS not configured")
		}
		return identity.DevIdentity(s.tenantID), nil
	}
	if token == "" {
		return identity.VerifiedIdentity{}, errIdentity("missing " + identity.HeaderNexQloudIdentity + " header")
	}

	verified, err := identity.VerifyIdentity([]byte(token), s.jwksURL, s.tenantID)
	if err != nil {
		return identity.VerifiedIdentity{}, errIdentity(err.Error())
	}
	return verified, nil
}

type identityError string

func (e identityError) Error() string { return string(e) }

func errIdentity(msg string) error {
	return identityError(msg)
}
