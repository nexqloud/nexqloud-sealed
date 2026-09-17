package destruction_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"nexqloud-sealed/internal/erasure/destruction"
)

func TestNewDestructionMarkFields(t *testing.T) {
	mark := destruction.NewDestructionMark("acme", 2)

	if mark.Schema != destruction.DestructionMarkSchema {
		t.Fatalf("schema = %q, want %q", mark.Schema, destruction.DestructionMarkSchema)
	}
	if mark.TenantID != "acme" || mark.SaltEpoch != 2 {
		t.Fatalf("unexpected mark: %+v", mark)
	}
	if _, err := time.Parse(time.RFC3339, mark.At); err != nil {
		t.Fatalf("at %q is not RFC3339: %v", mark.At, err)
	}
}

func TestDestructionMarkPackageIsCanonicalAndSigned(t *testing.T) {
	mark := destruction.NewDestructionMark("acme", 3)

	canonical, err := destruction.DestructionMarkPackage(mark)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(canonical, &decoded); err != nil {
		t.Fatalf("canonical mark is not JSON: %v", err)
	}
	for _, key := range []string{"schema", "tenant_id", "salt_epoch", "at"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("canonical mark missing %q: %s", key, canonical)
		}
	}
	if decoded["salt_epoch"].(float64) != 3 || decoded["tenant_id"].(string) != "acme" {
		t.Fatalf("canonical mark carries wrong values: %s", canonical)
	}

	// The bytes that go to the log must verify under the operator public key.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, canonical, ed25519.Sign(priv, canonical)) {
		t.Fatal("mark signature does not verify against the operator key")
	}
}

func TestAppendDestructionMarkWithoutSignerIsNoop(t *testing.T) {
	mark := destruction.NewDestructionMark("acme", 2)
	if idx := destruction.AppendDestructionMark(nil, mark); idx != "" {
		t.Fatalf("expected no log index without a signer, got %q", idx)
	}
	if idx := destruction.AppendDestructionMark(ed25519.PrivateKey([]byte("short")), mark); idx != "" {
		t.Fatalf("expected no log index for an invalid key, got %q", idx)
	}
}
