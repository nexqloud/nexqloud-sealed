package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"nexqloud-sealed/internal/attest"
	"nexqloud-sealed/internal/receipt"
)

func TestVerifyDerivationReceipt(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	attRaw := attest.TestAttestationJSON()
	digest, err := attest.ReportDigest(attRaw)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := hex.DecodeString(stringsTrimPrefix(digest, "sha256:"))
	if err != nil {
		t.Fatal(err)
	}
	tenantSum := sha256.Sum256([]byte("acme"))
	pkg := map[string]any{
		"schema":           receipt.DerivationSchema,
		"operator_id":      "operator-a",
		"attestation_hash": "sha256:" + hex.EncodeToString(sum),
		"tenant_id_hash":   "sha256:" + hex.EncodeToString(tenantSum[:]),
		"key_version":      1,
		"timestamp":        "2026-07-01T00:00:00Z",
	}

	canonical, err := canonicalizePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, canonical)

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	wrapper := ReceiptFile{
		Package:     pkg,
		Signature:   hex.EncodeToString(sig),
		Pubkey:      hex.EncodeToString(pub),
		Attestation: attRaw,
		Nonce:       hex.EncodeToString(nonce),
		LogIndex:    "0",
	}

	result := verifyDerivationReceipt(wrapper, "", nil)
	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}

	found := map[string]bool{}
	for _, check := range result.Checks {
		found[check.ID] = true
		if check.ID == "derivation_operator_id" && !check.OK {
			t.Fatalf("operator check failed: %s", check.Detail)
		}
		if check.ID == "derivation_attestation_hash" && !check.OK {
			t.Fatalf("attestation hash check failed: %s", check.Detail)
		}
		if check.ID == "signature_valid" && !check.OK {
			t.Fatalf("signature check failed: %s", check.Detail)
		}
	}

	for _, id := range []string{
		"signature_valid",
		"derivation_operator_id",
		"derivation_attestation_hash",
		"derivation_key_version",
		"derivation_tenant_hash",
	} {
		if !found[id] {
			t.Fatalf("missing check %s", id)
		}
	}

	if result.Schema != receipt.DerivationSchema {
		t.Fatalf("schema = %q", result.Schema)
	}
	if result.OperatorID != "operator-a" {
		t.Fatalf("operator_id = %q", result.OperatorID)
	}
}
