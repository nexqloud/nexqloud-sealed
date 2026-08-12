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
	"time"

	"github.com/google/uuid"

	"nexqloud-sealed/internal/gpu"
	"nexqloud-sealed/internal/gpu/wipe"
)

type zeroizeRequest struct {
	Nonce      string `json:"nonce"`
	PolicyHash string `json:"policy_hash"`
	GPUID      string `json:"gpu_id,omitempty"`
}

func main() {
	addr := strings.TrimSpace(os.Getenv("WIPE_LISTEN"))
	if addr == "" {
		addr = ":19001"
	}
	priv, err := loadIssuerKey()
	if err != nil {
		log.Fatalf("issuer key: %v", err)
	}
	issuer := strings.TrimSpace(os.Getenv("WIPE_ISSUER_ID"))
	if issuer == "" {
		issuer = "nexqloud-wipe-worker"
	}
	commitment, err := wipe.SelfCommitment()
	if err != nil {
		log.Fatalf("worker commitment: %v", err)
	}
	llamaURL := strings.TrimRight(strings.TrimSpace(os.Getenv("LLAMA_URL")), "/")
	kvRequired := envOr("WIPE_KV_REQUIRED", "1") != "0"
	log.Printf("wipe-worker listening on %s issuer=%s commitment=%s mode=%s llama_url=%q kv_required=%v",
		addr, issuer, commitment, envOr("WIPE_MODE", wipe.ModeCUDA), llamaURL, kvRequired)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/v1/zeroize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req zeroizeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		req.PolicyHash = strings.TrimSpace(req.PolicyHash)
		req.Nonce = strings.TrimSpace(req.Nonce)
		if req.PolicyHash == "" {
			http.Error(w, "policy_hash required", http.StatusBadRequest)
			return
		}

		var slotsErased []int
		kvCleared := false
		if llamaURL != "" {
			ids, err := wipe.EraseSlots(llamaURL, 15*time.Second)
			if err != nil {
				if kvRequired {
					http.Error(w, "kv erase failed: "+err.Error(), http.StatusInternalServerError)
					return
				}
				log.Printf("kv erase skipped (WIPE_KV_REQUIRED=0): %v", err)
			} else {
				slotsErased = ids
				kvCleared = true
			}
		} else if kvRequired {
			http.Error(w, "LLAMA_URL required for kv erase (set WIPE_KV_REQUIRED=0 to skip)", http.StatusInternalServerError)
			return
		}

		if err := wipe.TwoPass(); err != nil {
			http.Error(w, "wipe failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		gpuID := strings.TrimSpace(req.GPUID)
		if gpuID == "" {
			gpuID = envOr("NEXQLOUD_GPU_ID", "gpu-0")
		}
		cert := gpu.ZeroizationCert{
			Schema:           gpu.CertSchema,
			ClearanceID:      uuid.NewString(),
			GPUID:            gpuID,
			GPUModel:         strings.TrimSpace(os.Getenv("NEXQLOUD_GPU_MODEL")),
			Method:           gpu.MethodTwoPass,
			PolicyHash:       req.PolicyHash,
			Nonce:            req.Nonce,
			WorkerCommitment: commitment,
			KVCacheCleared:   kvCleared,
			SlotsErased:      slotsErased,
			WipedAt:          time.Now().UTC().Format(time.RFC3339),
			Issuer:           issuer,
		}
		signed, err := gpu.SignCert(cert, priv)
		if err != nil {
			http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
			return
		}
		m, err := gpu.CertToMap(signed)
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
	raw := strings.TrimSpace(os.Getenv("WIPE_ISSUER_PRIVKEY"))
	if raw == "" {
		if p := strings.TrimSpace(os.Getenv("WIPE_ISSUER_PRIVKEY_FILE")); p != "" {
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			raw = strings.TrimSpace(string(b))
		}
	}
	if raw == "" {
		return nil, fmt.Errorf("set WIPE_ISSUER_PRIVKEY or WIPE_ISSUER_PRIVKEY_FILE")
	}
	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode privkey hex: %w", err)
	}
	if len(b) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(b), nil
	}
	if len(b) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(b), nil
	}
	return nil, fmt.Errorf("privkey must be %d-byte seed or %d-byte key, got %d",
		ed25519.SeedSize, ed25519.PrivateKeySize, len(b))
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
