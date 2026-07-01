package destruction_test

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

	"nexqloud-sealed/internal/destruction"
	"nexqloud-sealed/internal/identity"
	"nexqloud-sealed/internal/registry"
	"nexqloud-sealed/internal/seen"
)

func TestCoordinatorRequiresCustomerAuth(t *testing.T) {
	identity.ResetCaches()
	seen.Reset()

	key, jwksURL := startTestJWKS(t)
	token := signTestJWT(t, key, "kid-1", map[string]any{
		"tenant_id": "acme",
		"purpose":   "delete",
		"exp":       time.Now().Add(time.Hour).Unix(),
	})

	regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := registry.CommitmentRecord{
			TenantID:   "acme",
			KeyVersion: 1,
			SeedCommit: "sha256:abc",
			Wraps:      map[string][]byte{"operator-a": {1}},
		}
		json.NewEncoder(w).Encode(rec)
	}))
	defer regSrv.Close()

	aggSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer aggSrv.Close()

	reg := registry.NewHTTPClient(regSrv.URL)
	coord := destruction.NewCoordinator(reg, aggSrv.URL, nil)
	sk, err := destruction.LoadCoordinatorKey("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	coord.SetAuth(jwksURL, sk)

	_, err = coord.CreateDestruction(t.Context(), destruction.CreateDestructionRequest{TenantID: "acme"})
	if err == nil {
		t.Fatal("expected unauthorized without customer jwt")
	}

	_, err = coord.CreateDestruction(t.Context(), destruction.CreateDestructionRequest{
		TenantID:    "acme",
		CustomerSig: []byte(token),
		Nonce:       "nonce-coord-1",
	})
	if err != nil {
		t.Fatal(err)
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
