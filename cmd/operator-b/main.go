package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"nexqloud-sealed/internal/kdf"
	"nexqloud-sealed/internal/registry"
	"nexqloud-sealed/internal/rootsecret"
	"nexqloud-sealed/internal/state"
)

const (
	tenantID   = "acme"
	keyVersion = 1
	operatorID = "operator-b"
	plaintext  = "federated-test-state"
)

func main() {
	registryURL := flag.String("registry", "http://127.0.0.1:7001", "federated registry base URL")
	stateFile := flag.String("state", "shared_state.bin", "path to sealed state from operator A")
	flag.Parse()

	ciphertext, err := os.ReadFile(*stateFile)
	if err != nil {
		log.Fatalf("read %s: %v", *stateFile, err)
	}

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

	opened, err := state.Open(dek, ciphertext)
	if err != nil {
		log.Fatalf("open sealed state: %v", err)
	}
	if !bytes.Equal(opened, []byte(plaintext)) {
		log.Fatalf("plaintext mismatch: got %q want %q", opened, plaintext)
	}

	fmt.Println("SUCCESS: Operator B opened A's sealed state")
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
