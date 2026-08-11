package signedclaim

import (
	"crypto/ed25519"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	claim := map[string]any{
		"schema": "test/1",
		"nonce":  "aabb",
		"value":  "hello",
	}
	if err := AttachSignature(claim, priv); err != nil {
		t.Fatal(err)
	}
	if claim["signature"] == "" || claim["pubkey"] == "" {
		t.Fatalf("missing sig fields: %#v", claim)
	}
	if err := Verify(claim, "test/1"); err != nil {
		t.Fatal(err)
	}
	claim["value"] = "tampered"
	if err := Verify(claim, "test/1"); err == nil {
		t.Fatal("expected verify fail after tamper")
	}
}
