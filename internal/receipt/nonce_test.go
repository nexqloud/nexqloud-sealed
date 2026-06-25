package receipt

import (
	"testing"
)

func TestValidateChallengeNonce(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := ValidateChallengeNonce(valid); err != nil {
		t.Fatalf("expected valid nonce: %v", err)
	}

	for _, bad := range []string{
		"",
		"abc",
		valid + "0",
		valid[:63],
		"g" + valid[1:],
	} {
		if bad == "" {
			continue
		}
		if err := ValidateChallengeNonce(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestResolveNonceRandom(t *testing.T) {
	nonce, hexStr, err := resolveNonce("")
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 32 || len(hexStr) != nonceHexLen {
		t.Fatalf("unexpected nonce lengths: %d %d", len(nonce), len(hexStr))
	}
}

func TestResolveNonceClientProvided(t *testing.T) {
	want := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	nonce, hexStr, err := resolveNonce(want)
	if err != nil {
		t.Fatal(err)
	}
	if hexStr != want {
		t.Fatalf("hex mismatch: %s", hexStr)
	}
	if len(nonce) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(nonce))
	}
}
