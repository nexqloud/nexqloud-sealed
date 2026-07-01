package identity

import (
	"crypto"
	"fmt"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

var (
	cacheMu sync.RWMutex
	caches  = make(map[string]*jwksCache)
)

func VerifySig(customerSig []byte, tenantID string, jwksURL string) error {
	if len(customerSig) == 0 {
		return fmt.Errorf("missing customer signature")
	}
	if tenantID == "" {
		return fmt.Errorf("missing tenant_id")
	}
	if jwksURL == "" {
		return fmt.Errorf("missing jwks url")
	}

	token, err := jwt.Parse(string(customerSig), func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method %q", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("missing kid in jwt header")
		}
		cache := jwksCacheFor(jwksURL)
		return cache.key(kid)
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	if err != nil {
		return fmt.Errorf("invalid jwt: %w", err)
	}
	if !token.Valid {
		return fmt.Errorf("invalid jwt")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid jwt claims")
	}

	claimTenant, _ := claims["tenant_id"].(string)
	if claimTenant == "" {
		claimTenant, _ = claims["sub"].(string)
	}
	if claimTenant != tenantID {
		return fmt.Errorf("tenant_id mismatch: got %q want %q", claimTenant, tenantID)
	}

	if purpose, _ := claims["purpose"].(string); purpose != "" && purpose != "delete" {
		return fmt.Errorf("unexpected purpose %q", purpose)
	}

	return nil
}

func jwksCacheFor(url string) *jwksCache {
	cacheMu.RLock()
	cache, ok := caches[url]
	cacheMu.RUnlock()
	if ok {
		return cache
	}

	cacheMu.Lock()
	defer cacheMu.Unlock()
	if cache, ok = caches[url]; ok {
		return cache
	}
	cache = newJWKSCache(url)
	caches[url] = cache
	return cache
}

func ResetCaches() {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	caches = make(map[string]*jwksCache)
}

func VerifySigWithKey(customerSig []byte, tenantID string, key crypto.PublicKey) error {
	if len(customerSig) == 0 {
		return fmt.Errorf("missing customer signature")
	}
	token, err := jwt.Parse(string(customerSig), func(t *jwt.Token) (any, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	if err != nil {
		return fmt.Errorf("invalid jwt: %w", err)
	}
	if !token.Valid {
		return fmt.Errorf("invalid jwt")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid jwt claims")
	}
	claimTenant, _ := claims["tenant_id"].(string)
	if claimTenant == "" {
		claimTenant, _ = claims["sub"].(string)
	}
	if strings.TrimSpace(claimTenant) != tenantID {
		return fmt.Errorf("tenant_id mismatch")
	}
	return nil
}
