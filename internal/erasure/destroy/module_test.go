package destroy_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nexqloud-sealed/internal/attest"
	"nexqloud-sealed/internal/derive/state"
	"nexqloud-sealed/internal/erasure/destroy"
	"nexqloud-sealed/internal/erasure/destruction"
	"nexqloud-sealed/internal/identity"
	"nexqloud-sealed/internal/registry"
	"nexqloud-sealed/internal/seen"
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

	// Evidence has to be measured, not asserted: the receipt must carry the real
	// salt roll (bootstrap epoch 1 -> 2) and the real zeroization outcomes.
	if got := rcpt.SaltEpoch(); got != 2 {
		t.Fatalf("receipt salt_epoch = %d, want 2", got)
	}
	var ev struct {
		WrapHash                  string `json:"wrap_hash"`
		CiphertextOverwritten     bool   `json:"ciphertext_overwritten"`
		ChipContributionDestroyed bool   `json:"chip_contribution_destroyed"`
		SaltRotated               bool   `json:"salt_rotated"`
	}
	if err := json.Unmarshal(rcpt.ZeroizationEvidenceJSON(), &ev); err != nil {
		t.Fatalf("zeroization evidence: %v", err)
	}
	if ev.WrapHash == "" || !ev.CiphertextOverwritten || !ev.ChipContributionDestroyed || !ev.SaltRotated {
		t.Fatalf("incomplete zeroization evidence: %+v", ev)
	}
}

func TestDestroyFailsClosedWhenSaltCannotRotate(t *testing.T) {
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
	wrap := state.Seal(chipSecret, []byte("seed-32-bytes-long-for-test!!!!!!"))

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

	// A salt path whose parent is a regular file can never be created, so the roll
	// cannot happen. Destroy must refuse to emit a receipt rather than claim success.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	destroy.Configure(destroy.RuntimeConfig{
		CoordinatorPub: coordPub,
		JWKSURL:        jwksURL,
		OperatorID:     "operator-a",
		StateDir:       dir,
		SaltPath:       filepath.Join(blocker, "federation_salt.json"),
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
		DestructionID: "dest-fail",
		TenantID:      "acme",
		KeyVersion:    1,
		SeedCommit:    "sha256:abc",
		OperatorID:    "operator-a",
		CustomerSig:   []byte(customerJWT),
	}
	sig, err := destruction.SignDispatch(coordPriv, req)
	if err != nil {
		t.Fatal(err)
	}
	req.CoordinatorSig = sig

	if _, err := destroy.Destroy(req, "acme"); err == nil {
		t.Fatal("expected Destroy to fail when the federation salt cannot be rolled")
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
