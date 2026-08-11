package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"nexqloud-sealed/internal/modelattest"
)

type attestRequest struct {
	Nonce string `json:"nonce"`
}

func main() {
	addr := strings.TrimSpace(os.Getenv("MODEL_ATTEST_LISTEN"))
	if addr == "" {
		addr = ":19002"
	}
	modelPath := strings.TrimSpace(os.Getenv("MODEL_PATH"))
	if modelPath == "" {
		log.Fatal("MODEL_PATH is required")
	}
	priv, err := loadIssuerKey()
	if err != nil {
		log.Fatalf("issuer key: %v", err)
	}
	issuer := strings.TrimSpace(os.Getenv("MODEL_ATTEST_ISSUER_ID"))
	if issuer == "" {
		issuer = "nexqloud-model-attest"
	}
	modelID := strings.TrimSpace(os.Getenv("NEXQLOUD_MODEL_ID"))

	log.Printf("hashing model at %s …", modelPath)
	commitment, err := modelattest.HashFile(modelPath)
	if err != nil {
		log.Fatalf("hash model: %v", err)
	}
	log.Printf("model-attest listening on %s issuer=%s model_id=%s commitment=%s",
		addr, issuer, modelID, commitment)

	var mu sync.RWMutex
	cached := commitment

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":           "ok",
			"model_commitment": cached,
			"model_id":         modelID,
		})
	})
	mux.HandleFunc("/v1/attest-model", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req attestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		req.Nonce = strings.TrimSpace(req.Nonce)
		if req.Nonce == "" {
			http.Error(w, "nonce required", http.StatusBadRequest)
			return
		}
		mu.RLock()
		c := cached
		mu.RUnlock()

		cert := modelattest.NewCert(c, modelID, req.Nonce, issuer)
		signed, err := modelattest.SignCert(cert, priv)
		if err != nil {
			http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
			return
		}
		m, err := signed.ToMap()
		if err != nil {
			http.Error(w, "encode: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m)
	})

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func loadIssuerKey() (ed25519.PrivateKey, error) {
	raw := strings.TrimSpace(os.Getenv("MODEL_ATTEST_ISSUER_PRIVKEY"))
	if raw == "" {
		return nil, fmt.Errorf("MODEL_ATTEST_ISSUER_PRIVKEY required (32-byte hex seed or 64-byte hex private key)")
	}
	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode privkey hex: %w", err)
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	default:
		return nil, fmt.Errorf("privkey must be %d-byte seed or %d-byte key, got %d bytes",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(b))
	}
}
