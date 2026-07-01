package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/gowebpki/jcs"
)

func TestDerivationReceiptPackageFields(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	att := []byte(`{"report":{"version":2}}`)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	pkg := map[string]any{
		"schema":           DerivationSchema,
		"operator_id":      "operator-a",
		"attestation_hash": digestBytes(att),
		"tenant_id_hash":   digestBytes([]byte("acme")),
		"key_version":      1,
		"timestamp":        "2026-07-01T00:00:00Z",
	}

	canonical, err := canonicalize(pkg)
	if err != nil {
		t.Fatal(err)
	}

	sig := ed25519.Sign(priv, canonical)
	if !ed25519.Verify(pub, canonical, sig) {
		t.Fatal("signature verification failed")
	}

	raw, err := json.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	jcsBytes, err := jcs.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, jcsBytes, sig) {
		t.Fatal("jcs signature verification failed")
	}

	if pkg["schema"] != DerivationSchema {
		t.Fatalf("schema = %v", pkg["schema"])
	}
	if pkg["operator_id"] != "operator-a" {
		t.Fatalf("operator_id = %v", pkg["operator_id"])
	}
	if pkg["attestation_hash"] != digestBytes(att) {
		t.Fatalf("attestation_hash = %v", pkg["attestation_hash"])
	}
	if pkg["tenant_id_hash"] != digestBytes([]byte("acme")) {
		t.Fatalf("tenant_id_hash = %v", pkg["tenant_id_hash"])
	}
	if pkg["key_version"] != 1 {
		t.Fatalf("key_version = %v", pkg["key_version"])
	}

	_ = hex.EncodeToString(sig)
}
