package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	"nexqloud-sealed/internal/enclave"
	"nexqloud-sealed/internal/kdf"
	"nexqloud-sealed/internal/registry"
	"nexqloud-sealed/internal/receipt"
	"nexqloud-sealed/internal/rootsecret"
	"nexqloud-sealed/internal/state"
)

const (
	tenantID   = "acme"
	keyVersion = 1
	operatorID = "operator-a"
	plaintext  = "federated-test-state"
)

func main() {
	registryURL := flag.String("registry", "http://127.0.0.1:7001", "federated registry base URL")
	stateFile := flag.String("state", "shared_state.bin", "output path for sealed state")
	receiptFile := flag.String("receipt", "derivation_receipt.json", "output path for derivation receipt")
	flag.Parse()

	chipSecret, err := rootsecret.Chip()
	if err != nil {
		log.Fatalf("chip secret: %v", err)
	}

	wrappedSeed, err := fetchWrap(*registryURL, tenantID, operatorID)
	if err != nil {
		log.Fatalf("fetch wrap: %v", err)
	}

	seed, err := state.Open(chipSecret, wrappedSeed)
	if err != nil {
		log.Fatalf("unwrap seed: %v", err)
	}

	claimHash := federationClaimHash()
	attestBind := federationAttestBind(claimHash)

	dek, err := kdf.DeriveDEK(seed, chipSecret, claimHash, attestBind, tenantID, keyVersion)
	if err != nil {
		log.Fatalf("derive DEK: %v", err)
	}

	ciphertext := state.Seal(dek, []byte(plaintext))
	if err := os.WriteFile(*stateFile, ciphertext, 0o600); err != nil {
		log.Fatalf("write %s: %v", *stateFile, err)
	}

	priv, pub, err := enclave.Key()
	if err != nil {
		log.Fatalf("enclave key: %v", err)
	}

	attBytes, nonce, err := operatorAttestation(pub)
	if err != nil {
		log.Fatalf("attestation: %v", err)
	}

	rcpt := receipt.DerivationReceipt(priv, pub, operatorID, attBytes, tenantID, keyVersion, nonce)
	receiptJSON, err := json.MarshalIndent(rcpt, "", "  ")
	if err != nil {
		log.Fatalf("marshal receipt: %v", err)
	}
	if err := os.WriteFile(*receiptFile, receiptJSON, 0o600); err != nil {
		log.Fatalf("write %s: %v", *receiptFile, err)
	}

	fmt.Printf("wrote sealed state to %s and derivation receipt to %s\n", *stateFile, *receiptFile)
}

func fetchWrap(registryURL, tenantID, operatorID string) ([]byte, error) {
	url := fmt.Sprintf("%s/records/%s", strings.TrimRight(registryURL, "/"), tenantID)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var record registry.CommitmentRecord
	if err := json.Unmarshal(body, &record); err != nil {
		return nil, err
	}

	wrap, ok := record.Wraps[operatorID]
	if !ok {
		return nil, fmt.Errorf("wrap for %q not found", operatorID)
	}
	return wrap, nil
}

func federationClaimHash() []byte {
	claimHash := make([]byte, 32)
	for i := range claimHash {
		claimHash[i] = byte(i * 3)
	}
	return claimHash
}

func federationAttestBind(claimHash []byte) []byte {
	return append([]byte("sealed-federation/v1/"), claimHash...)
}

func operatorAttestation(pub ed25519.PublicKey) ([]byte, []byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	att, err := enclave.RequestReport(pub, nonce)
	if err != nil {
		return nil, nil, err
	}
	attBytes, err := protojson.Marshal(att)
	if err != nil {
		return nil, nil, err
	}
	return attBytes, nonce, nil
}
