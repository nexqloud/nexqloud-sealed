package destroy_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"nexqloud-sealed/internal/destroy"
	"nexqloud-sealed/internal/identity"
	"nexqloud-sealed/internal/seen"
)

func TestAcceptValidRequest(t *testing.T) {
	identity.ResetCaches()
	seen.Reset()

	key, jwksURL := startTestJWKS(t)
	token := signTestJWT(t, key, "kid-1", map[string]any{
		"tenant_id": "acme",
		"purpose":   "delete",
		"exp":       time.Now().Add(time.Hour).Unix(),
	})

	err := destroy.Accept(destroy.DeleteRequest{
		TenantID:    "acme",
		CustomerSig: []byte(token),
		Nonce:       "nonce-accept-1",
	}, jwksURL)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAcceptRejectsReplayNonce(t *testing.T) {
	identity.ResetCaches()
	seen.Reset()

	key, jwksURL := startTestJWKS(t)
	token := signTestJWT(t, key, "kid-1", map[string]any{
		"tenant_id": "acme",
		"exp":       time.Now().Add(time.Hour).Unix(),
	})

	req := destroy.DeleteRequest{
		TenantID:    "acme",
		CustomerSig: []byte(token),
		Nonce:       "nonce-replay",
	}
	if err := destroy.Accept(req, jwksURL); err != nil {
		t.Fatal(err)
	}
	if err := destroy.Accept(req, jwksURL); err == nil {
		t.Fatal("expected replay rejection")
	}
}

func startTestJWKS(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": "kid-1",
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	return key, srv.URL
}

func signTestJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
