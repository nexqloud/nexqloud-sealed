package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"nexqloud-sealed/internal/devmode"
	"nexqloud-sealed/internal/enclave"
	"nexqloud-sealed/internal/identity"
	"nexqloud-sealed/internal/inference"
	"nexqloud-sealed/internal/receipt"
)

const defaultAddr = ":8080"

type server struct {
	inference inference.Backend
	receipt   *receipt.Builder
	jwksURL   string
	tenantID  string
	ready     atomic.Bool
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
		jwksURL:  strings.TrimSpace(*jwksURL),
		tenantID: strings.TrimSpace(*tenantID),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		status := "starting"
		if srv.ready.Load() {
			status = "ok"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if !srv.ready.Load() {
			http.Error(w, "sealed-shim still starting", http.StatusServiceUnavailable)
			return
		}
		srv.handleChatCompletions(w, r)
	})

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

	srv.inference = selectInferenceBackend()
	srv.receipt = receipt.NewBuilder(priv, pub)

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
	log.Printf("sealed-shim ready (inference=%T, dev=%v)", srv.inference, devmode.Enabled())
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

	identityHash, err := s.verifyIdentity(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	inferOut, err := s.inference.Complete(req)
	if err != nil {
		http.Error(w, "inference failed", http.StatusBadGateway)
		return
	}

	sealedReceipt, err := s.receipt.Seal(receipt.Input{
		Prompt:            extractPrompt(req),
		Response:          inferOut.Content,
		ChallengeNonce:    req.ChallengeNonce,
		IdentityClaimHash: identityHash,
	})
	if err != nil {
		log.Printf("receipt build failed: %v", err)
		http.Error(w, "receipt build failed", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"id":      "chatcmpl-" + uuid.NewString(),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   inferOut.Model,
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": inferOut.Content,
				},
				"finish_reason": "stop",
			},
		},
		"sealed_receipt": sealedReceipt,
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(resp); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func (s *server) verifyIdentity(r *http.Request) (string, error) {
	token := strings.TrimSpace(r.Header.Get(identity.HeaderNexQloudIdentity))
	if s.jwksURL == "" {
		if token != "" {
			log.Printf("identity: ignoring %s (JWKS not configured)", identity.HeaderNexQloudIdentity)
		}
		if !devmode.Enabled() {
			return "", errIdentity("JWKS not configured")
		}
		return "", nil
	}
	if token == "" {
		return "", errIdentity("missing " + identity.HeaderNexQloudIdentity + " header")
	}

	verified, err := identity.VerifyIdentity([]byte(token), s.jwksURL, s.tenantID)
	if err != nil {
		return "", errIdentity(err.Error())
	}
	return verified.Hash, nil
}

type identityError string

func (e identityError) Error() string { return string(e) }

func errIdentity(msg string) error {
	return identityError(msg)
}

func extractPrompt(req inference.Request) string {
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			return req.Messages[i].Content
		}
	}
	if len(req.Messages) > 0 {
		return req.Messages[len(req.Messages)-1].Content
	}
	return ""
}
