//go:build !(js && wasm)

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"nexqloud-sealed/internal/attest"
	"nexqloud-sealed/internal/devmode"
	"nexqloud-sealed/internal/enclave"
	"nexqloud-sealed/internal/erasure/destroy"
	"nexqloud-sealed/internal/operatorsurface"
	"nexqloud-sealed/internal/receipt"
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
		MarkSigner:     priv,
		// Destroying the registry-held wrap is what makes the erasure durable: the
		// local cache and file are overwritten too, but without this an operator
		// restart would refetch the material that was supposedly erased.
		DestroyRegistryWrap: func(tenantID string) error {
			return reg.DestroyWrap(tenantID, *operatorID)
		},
		SignReceipt: func(input destroy.ReceiptInput) (destroy.Receipt, error) {
			nonce, err := destroy.RandomNonce()
			if err != nil {
				return destroy.Receipt{}, err
			}
			attJSON, err := operatorAttestation(pub, nonce)
			if err != nil {
				if !devmode.Enabled() {
					return destroy.Receipt{}, fmt.Errorf("attestation: %w", err)
				}
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
	operatorsurface.Register(mux, operatorsurface.Config{
		Registry:   reg,
		OperatorID: *operatorID,
		StateDir:   *stateDir,
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("operator %s listening on %s (pubkey %s)", *operatorID, *addr, hex.EncodeToString(pub))
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func operatorAttestation(pub ed25519.PublicKey, nonce []byte) ([]byte, error) {
	att, err := enclave.RequestReport(pub, nonce)
	if err != nil {
		return nil, err
	}
	return receipt.MarshalAttestation(att)
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
