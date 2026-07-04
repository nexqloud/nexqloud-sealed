package identity_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"nexqloud-sealed/internal/identity"
)

func TestVerifyIdentity(t *testing.T) {
	identity.ResetCaches()

	key, jwksURL := startTestJWKS(t)
	token := signTestJWT(t, key, "kid-1", map[string]any{
		"sub":       "user-42",
		"tenant_id": "acme",
		"aud":       "nexqloud-inference",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	})

	verified, err := identity.VerifyIdentity([]byte(token), jwksURL, "acme")
	if err != nil {
		t.Fatalf("VerifyIdentity: %v", err)
	}
	if verified.Hash == "" || verified.Hash[:7] != "sha256:" {
		t.Fatalf("hash = %q", verified.Hash)
	}

	again, err := identity.CommitmentHash(verified.Claims)
	if err != nil {
		t.Fatal(err)
	}
	if again != verified.Hash {
		t.Fatalf("hash mismatch: %q vs %q", again, verified.Hash)
	}
}

func TestVerifyIdentityRejectsDeleteToken(t *testing.T) {
	identity.ResetCaches()

	key, jwksURL := startTestJWKS(t)
	token := signTestJWT(t, key, "kid-1", map[string]any{
		"tenant_id": "acme",
		"purpose":   "delete",
		"exp":       time.Now().Add(time.Hour).Unix(),
	})

	if _, err := identity.VerifyIdentity([]byte(token), jwksURL, "acme"); err == nil {
		t.Fatal("expected delete token rejection")
	}
}

func TestVerifyIdentityRequiresHeaderWhenConfigured(t *testing.T) {
	identity.ResetCaches()

	key, jwksURL := startTestJWKS(t)
	_, err := identity.VerifyIdentity(nil, jwksURL, "")
	if err == nil {
		t.Fatal("expected missing token error")
	}

	token := signTestJWT(t, key, "kid-1", map[string]any{
		"tenant_id": "other",
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	if _, err := identity.VerifyIdentity([]byte(token), jwksURL, "acme"); err == nil {
		t.Fatal("expected tenant mismatch")
	}
}

func TestCommitmentHashDeterministic(t *testing.T) {
	claims := jwt.MapClaims{
		"sub":       "user-1",
		"tenant_id": "acme",
		"aud":       "nexqloud",
		"iat":       float64(1_700_000_000),
		"exp":       float64(1_700_000_600),
	}
	h1, err := identity.CommitmentHash(claims)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := identity.CommitmentHash(claims)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("not deterministic: %q vs %q", h1, h2)
	}
}
