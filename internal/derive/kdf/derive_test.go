package kdf

import (
	"bytes"
	"testing"
)

func TestDeriveDEK_Determinism(t *testing.T) {
	seed := []byte("dummy-seed-material")
	chipSecret := []byte("dummy-chip-secret")
	claimHash := make([]byte, 32)
	for i := range claimHash {
		claimHash[i] = byte(i)
	}
	attestBind := []byte("dummy-attest-bind")

	dek1, err := DeriveDEK(seed, chipSecret, claimHash, attestBind, "acme", 1)
	if err != nil {
		t.Fatalf("first DeriveDEK: %v", err)
	}
	dek2, err := DeriveDEK(seed, chipSecret, claimHash, attestBind, "acme", 1)
	if err != nil {
		t.Fatalf("second DeriveDEK: %v", err)
	}

	if len(dek1) != 32 || len(dek2) != 32 {
		t.Fatalf("expected 32-byte keys, got %d and %d", len(dek1), len(dek2))
	}
	if !bytes.Equal(dek1, dek2) {
		t.Fatalf("DeriveDEK is not deterministic:\n  %x\n  %x", dek1, dek2)
	}
}
