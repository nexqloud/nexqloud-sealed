package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	"nexqloud-sealed/internal/attest"
	"nexqloud-sealed/internal/destruction"
	"nexqloud-sealed/internal/destroy"
	"nexqloud-sealed/internal/enclave"
	"nexqloud-sealed/internal/registry"
)

func main() {
	registryURL := flag.String("registry", "http://127.0.0.1:7001", "federated registry base URL")
	operatorID := flag.String("operator-id", "operator-a", "operator identity")
	addr := flag.String("addr", ":7101", "listen address")
	jwksURL := flag.String("jwks", "", "customer IdP JWKS URL")
	coordinatorPubHex := flag.String("coordinator-pub-hex", "", "coordinator Ed25519 public key hex")
	stateDir := flag.String("state-dir", ".", "directory for tenant ciphertext and wrap cache")
	flag.Parse()

	if *jwksURL == "" {
		log.Fatal("jwks URL is required")
	}
	coordPub, err := loadCoordinatorPub(*coordinatorPubHex)
	if err != nil {
		log.Fatalf("coordinator pubkey: %v", err)
	}

	reg := registry.NewHTTPClient(*registryURL)
	local := registry.NewLocalStore(*operatorID, reg, *stateDir)
	registry.ConfigureLocal(local)

	priv, pub, err := enclave.Key()
	if err != nil {
		log.Fatalf("enclave key: %v", err)
	}

	destroy.Configure(destroy.RuntimeConfig{
		CoordinatorPub: coordPub,
		JWKSURL:        *jwksURL,
		OperatorID:     *operatorID,
		StateDir:       *stateDir,
		LocalStore:     local,
		Attestation:    operatorAttestation,
		SignReceipt: func(input destroy.ReceiptInput) (destroy.Receipt, error) {
			nonce, err := destroy.RandomNonce()
			if err != nil {
				return destroy.Receipt{}, err
			}
			attJSON, err := operatorAttestation(pub, nonce)
			if err != nil {
				attJSON = attest.TestAttestationJSON()
			}
			input.Priv = priv
			input.Pub = pub
			input.OperatorID = *operatorID
			input.Nonce = nonce
			input.AttestationJSON = attJSON
			return destroy.BuildReceipt(input)
		},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/destruction", handleDestruction)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("operator %s listening on %s (pubkey %s)", *operatorID, *addr, hex.EncodeToString(pub))
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func handleDestruction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var req destruction.SignedDestroyReq
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	rcpt, err := destroy.Destroy(req, req.TenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if req.AggregatorSubmitURL != "" {
		payload, err := json.Marshal(rcpt)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp, err := http.Post(req.AggregatorSubmitURL, "application/json", bytes.NewReader(payload))
		if err != nil {
			http.Error(w, fmt.Sprintf("submit receipt: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			http.Error(w, fmt.Sprintf("aggregator %s: %s", resp.Status, strings.TrimSpace(string(respBody))), http.StatusBadGateway)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(rcpt)
}

func operatorAttestation(pub ed25519.PublicKey, nonce []byte) ([]byte, error) {
	att, err := enclave.RequestReport(pub, nonce)
	if err != nil {
		return nil, err
	}
	return protojson.Marshal(att)
}

func loadCoordinatorPub(hexPub string) (ed25519.PublicKey, error) {
	if hexPub == "" {
		if v := strings.TrimSpace(os.Getenv("COORDINATOR_PUB_HEX")); v != "" {
			hexPub = v
		}
	}
	if hexPub == "" {
		return nil, fmt.Errorf("coordinator public key required (-coordinator-pub-hex)")
	}
	raw, err := hex.DecodeString(hexPub)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("coordinator pub length %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

var _ = sha256.Sum256
var _ = rand.Reader
