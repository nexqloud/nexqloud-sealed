package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const keyID = "mock-idp-1"

func main() {
	addr := flag.String("addr", ":7200", "listen address")
	tenantID := flag.String("tenant", "acme", "tenant_id claim for minted JWT")
	nonce := flag.String("nonce", "", "optional nonce claim (generated if empty)")
	serveOnly := flag.Bool("serve-only", false, "only serve JWKS, do not print a JWT")
	flag.Parse()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	jwks := buildJWKS(key)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	go func() {
		log.Printf("mock IdP JWKS at http://127.0.0.1%s/.well-known/jwks.json", *addr)
		log.Fatal(http.ListenAndServe(*addr, mux))
	}()

	time.Sleep(100 * time.Millisecond)

	jwksURL := fmt.Sprintf("http://127.0.0.1%s/.well-known/jwks.json", *addr)
	if *serveOnly {
		select {}
	}

	n := *nonce
	if n == "" {
		n = randomNonce()
	}

	token := mintJWT(key, *tenantID, n)
	fmt.Printf("JWKS_URL=%s\n", jwksURL)
	fmt.Printf("TENANT_ID=%s\n", *tenantID)
	fmt.Printf("NONCE=%s\n", n)
	fmt.Printf("CUSTOMER_JWT=%s\n", token)
	fmt.Fprintf(os.Stderr, "mock IdP listening on %s\n", *addr)
	select {}
}

func buildJWKS(key *rsa.PrivateKey) map[string]any {
	return map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": keyID,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}},
	}
}

func mintJWT(key *rsa.PrivateKey, tenantID, nonce string) string {
	claims := jwt.MapClaims{
		"tenant_id": tenantID,
		"purpose":   "delete",
		"nonce":     nonce,
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	signed, err := token.SignedString(key)
	if err != nil {
		log.Fatal(err)
	}
	return signed
}

func randomNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
