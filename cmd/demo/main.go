package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"log"

	"nexqloud-sealed/internal/kdf"
	"nexqloud-sealed/internal/receipt"
	"nexqloud-sealed/internal/state"
)

const (
	tenantID   = "acme"
	keyVersion = 1
	plaintext  = "federated-test-state"
)

func main() {
	chipSecretA := make([]byte, 32)
	chipSecretB := make([]byte, 32)
	for i := range chipSecretA {
		chipSecretA[i] = byte(i)
	}
	for i := range chipSecretB {
		chipSecretB[i] = byte(255 - i)
	}
	if bytes.Equal(chipSecretA, chipSecretB) {
		log.Fatal("chip secrets must be different")
	}

	claimHash := make([]byte, 32)
	for i := range claimHash {
		claimHash[i] = byte(i * 3)
	}

	attestBindA := []byte("operator-a-attest-bind")
	attestBindB := []byte("operator-b-attest-bind")
	if bytes.Equal(attestBindA, attestBindB) {
		log.Fatal("attest binds must be different")
	}

	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		log.Fatalf("generate seed: %v", err)
	}

	wrappedA := state.Seal(chipSecretA, seed)
	wrappedB := state.Seal(chipSecretB, seed)

	seedA, err := state.Open(chipSecretA, wrappedA)
	if err != nil {
		log.Fatalf("operator A unwrap seed: %v", err)
	}
	dekA, err := kdf.DeriveDEK(seedA, chipSecretA, claimHash, attestBindA, tenantID, keyVersion)
	if err != nil {
		log.Fatalf("operator A derive DEK: %v", err)
	}
	ciphertext := state.Seal(dekA, []byte(plaintext))
	_ = receipt.DerivationReceipt("operator-a", []byte("dummy-attestation-a"), tenantID, keyVersion)

	seedB, err := state.Open(chipSecretB, wrappedB)
	if err != nil {
		log.Fatalf("operator B unwrap seed: %v", err)
	}
	federatedAttestBind := attestBindA
	dekB, err := kdf.DeriveDEK(seedB, chipSecretA, claimHash, federatedAttestBind, tenantID, keyVersion)
	if err != nil {
		log.Fatalf("operator B derive DEK: %v", err)
	}

	opened, err := state.Open(dekB, ciphertext)
	if err != nil {
		log.Fatalf("operator B decrypt state: %v", err)
	}
	if !bytes.Equal(opened, []byte(plaintext)) {
		log.Fatalf("plaintext mismatch: got %q want %q", opened, plaintext)
	}

	fmt.Println("SUCCESS: Operator B decrypted Operator A's federated state, proving the derived DEKs are identical despite different chip secrets.")
}
