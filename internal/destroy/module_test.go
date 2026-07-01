package destroy_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nexqloud-sealed/internal/attest"
	"nexqloud-sealed/internal/destruction"
	"nexqloud-sealed/internal/destroy"
	"nexqloud-sealed/internal/identity"
	"nexqloud-sealed/internal/registry"
	"nexqloud-sealed/internal/seen"
	"nexqloud-sealed/internal/state"
)

func TestDestroyErasesWrapAndWritesReceipt(t *testing.T) {
	identity.ResetCaches()
	seen.Reset()

	coordPub, coordPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, opPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	key, jwksURL := startTestJWKS(t)
	customerJWT := signTestJWT(t, key, "kid-1", map[string]any{
		"tenant_id": "acme",
		"purpose":   "delete",
		"exp":       time.Now().Add(time.Hour).Unix(),
	})

	chipSecret := make([]byte, 32)
	copy(chipSecret, []byte("chip-secret-32-bytes-long!!!!!!"))
	seed := make([]byte, 32)
	copy(seed, []byte("seed-32-bytes-long-for-test!!!!!!"))
	wrap := state.Seal(chipSecret, seed)

	reg := &mockRegistryClient{records: map[string]registry.CommitmentRecord{
		"acme": {
			TenantID:   "acme",
			KeyVersion: 1,
			SeedCommit: "sha256:abc",
			Wraps:      map[string][]byte{"operator-a": wrap},
		},
	}}

	dir := t.TempDir()
	local := registry.NewLocalStore("operator-a", reg, dir)
	registry.ConfigureLocal(local)

	ciphertextPath := filepath.Join(dir, "acme.bin")
	if err := os.WriteFile(ciphertextPath, []byte("secret-state"), 0o600); err != nil {
		t.Fatal(err)
	}

	destroy.Configure(destroy.RuntimeConfig{
		CoordinatorPub: coordPub,
		JWKSURL:        jwksURL,
		OperatorID:     "operator-a",
		StateDir:       dir,
		LocalStore:     local,
		ChipSecret: func() ([]byte, error) {
			out := make([]byte, 32)
			copy(out, chipSecret)
			return out, nil
		},
		SignReceipt: func(input destroy.ReceiptInput) (destroy.Receipt, error) {
			input.Priv = opPriv
			input.Pub = opPriv.Public().(ed25519.PublicKey)
			input.OperatorID = "operator-a"
			input.AttestationJSON = attest.TestAttestationJSON()
			input.Nonce = make([]byte, 32)
			return destroy.BuildReceipt(input)
		},
	})

	req := destruction.SignedDestroyReq{
		DestructionID:       "dest-1",
		TenantID:            "acme",
		KeyVersion:          1,
		SeedCommit:          "sha256:abc",
		OperatorID:          "operator-a",
		AggregatorSubmitURL: "http://example.invalid/receipts",
		CustomerSig:         []byte(customerJWT),
	}
	sig, err := destruction.SignDispatch(coordPriv, req)
	if err != nil {
		t.Fatal(err)
	}
	req.CoordinatorSig = sig

	rcpt, err := destroy.Destroy(req, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := destruction.VerifyReceipt(rcpt); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(ciphertextPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) == "secret-state" {
		t.Fatal("ciphertext was not overwritten")
	}

	_, err = registry.LocalWrap("acme")
	if err != nil {
		t.Fatal(err)
	}
}

type mockRegistryClient struct {
	records map[string]registry.CommitmentRecord
}

func (m *mockRegistryClient) Get(tenantID string) (registry.CommitmentRecord, error) {
	rec, ok := m.records[tenantID]
	if !ok {
		return registry.CommitmentRecord{}, fmt.Errorf("record not found")
	}
	return rec, nil
}
