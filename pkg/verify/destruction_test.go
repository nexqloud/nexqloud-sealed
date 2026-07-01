package verify_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"nexqloud-sealed/internal/attest"
	"nexqloud-sealed/internal/destruction"
	"nexqloud-sealed/internal/destroy"
	"nexqloud-sealed/pkg/verify"
)

func TestVerifyDeletionProofAndReceipts(t *testing.T) {
	_, opAPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, opBPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, substrateSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tenantHash := destroy.TenantIDHash("acme")
	evidence := destroy.NewZeroizationEvidence("sha256:abc", true, true, true)
	att := attest.TestAttestationJSON()

	build := func(priv ed25519.PrivateKey, op string) destruction.Receipt {
		rcpt, err := destroy.BuildReceipt(destroy.ReceiptInput{
			Priv:            priv,
			Pub:             priv.Public().(ed25519.PublicKey),
			OperatorID:      op,
			DestructionID:   "dest-verify",
			TenantIDHash:    tenantHash,
			SeedCommit:      "sha256:seed",
			KeyVersion:      1,
			SaltEpoch:       2,
			AttestationJSON: att,
			Nonce:           make([]byte, 32),
			Evidence:        evidence,
		})
		if err != nil {
			t.Fatal(err)
		}
		return rcpt
	}

	receipts := []destruction.Receipt{
		build(opAPriv, "operator-a"),
		build(opBPriv, "operator-b"),
	}
	want := []string{"operator-a", "operator-b"}
	proof, err := destruction.Aggregate(want, receipts, "dest-verify", substrateSK)
	if err != nil {
		t.Fatal(err)
	}

	result := verify.VerifyDeletion(proof, receipts, "", "acme", "", nil)
	required := map[string]bool{
		"signature_valid":              true,
		"destruction_attestation_hash":   true,
		"zeroization_evidence":         true,
		"salt_epoch":                   true,
		"destruction_tenant_hash":      true,
		"proof_signature":              true,
		"merkle_root":                  true,
	}
	found := map[string]bool{}
	for _, check := range result.Checks {
		if want, ok := required[check.ID]; ok {
			found[check.ID] = true
			if want && !check.OK {
				t.Fatalf("check %s failed: %s", check.ID, check.Detail)
			}
		}
	}
	for id := range required {
		if !found[id] {
			t.Fatalf("missing check %s", id)
		}
	}
}
