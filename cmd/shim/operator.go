//go:build !(js && wasm)

package main

import (
	"crypto/ed25519"
	"encoding/hex"
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

// enableOperatorSurface turns a sealed deployment into a destruction-quorum member:
// it can seal a conversation scope's seed and, on a coordinator-signed order, zeroize
// that material and return a hardware-attested receipt.
//
// It is off unless the deployment is told where the substrate is, so a shim without
// these variables behaves exactly as before.
func enableOperatorSurface(mux *http.ServeMux, srv *server, priv ed25519.PrivateKey, pub ed25519.PublicKey) {
	registryURL := strings.TrimSpace(os.Getenv("NEXQLOUD_REGISTRY_URL"))
	operatorID := strings.TrimSpace(os.Getenv("NEXQLOUD_OPERATOR_ID"))
	coordinatorHex := strings.TrimSpace(os.Getenv("NEXQLOUD_COORDINATOR_PUB_HEX"))
	stateDir := strings.TrimSpace(os.Getenv("NEXQLOUD_STATE_DIR"))

	if registryURL == "" || operatorID == "" || coordinatorHex == "" {
		log.Printf("operator surface disabled (needs NEXQLOUD_REGISTRY_URL, NEXQLOUD_OPERATOR_ID and NEXQLOUD_COORDINATOR_PUB_HEX)")
		return
	}
	if stateDir == "" {
		stateDir = "."
	}

	coordPub, err := parseCoordinatorPub(coordinatorHex)
	if err != nil {
		log.Fatalf("coordinator pubkey: %v", err)
	}

	regClient := registry.NewHTTPClient(registryURL)
	local := registry.NewLocalStore(operatorID, regClient, stateDir)
	registry.ConfigureLocal(local)

	destroy.Configure(destroy.RuntimeConfig{
		CoordinatorPub: coordPub,
		JWKSURL:        srv.jwksURL,
		OperatorID:     operatorID,
		StateDir:       stateDir,
		LocalStore:     local,
		MarkSigner:     priv,
		// Destroying the registry-held wrap is what makes the erasure durable: the
		// local cache and file are overwritten too, but without this a restart would
		// refetch the material that was supposedly erased.
		DestroyRegistryWrap: func(tenantID string) error {
			return regClient.DestroyWrap(tenantID, operatorID)
		},
		SignReceipt: func(input destroy.ReceiptInput) (destroy.Receipt, error) {
			nonce, err := destroy.RandomNonce()
			if err != nil {
				return destroy.Receipt{}, err
			}
			attJSON, err := shimAttestation(pub, nonce)
			if err != nil {
				if !devmode.Enabled() {
					return destroy.Receipt{}, fmt.Errorf("attestation: %w", err)
				}
				attJSON = attest.TestAttestationJSON()
			}
			input.Priv = priv
			input.Pub = pub
			input.OperatorID = operatorID
			input.Nonce = nonce
			input.AttestationJSON = attJSON
			return destroy.BuildReceipt(input)
		},
	})

	operatorsurface.Register(mux, operatorsurface.Config{
		Registry:   regClient,
		OperatorID: operatorID,
		StateDir:   stateDir,
		// How a coordinator reaches this deployment; empty means the operator map
		// configured on the coordinator is used instead.
		CallbackURL: strings.TrimSpace(os.Getenv("NEXQLOUD_CALLBACK_URL")),
	})
}

func shimAttestation(pub ed25519.PublicKey, nonce []byte) ([]byte, error) {
	att, err := enclave.RequestReport(pub, nonce)
	if err != nil {
		return nil, err
	}
	// The verifier's hardware check needs the VCEK, and the derivation path refuses to
	// mint a receipt without it. AttachCertificateChain fills the chain from the warm
	// cache (or AMD KDS) and errors when no VCEK can be attached, so a destruction
	// receipt can no longer be minted with an unverifiable chain.
	if err := enclave.AttachCertificateChain(att); err != nil {
		return nil, err
	}
	return receipt.MarshalAttestation(att)
}

func parseCoordinatorPub(hexPub string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(hexPub))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("coordinator pub length %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
