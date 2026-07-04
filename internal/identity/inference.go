package identity

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type VerifiedIdentity struct {
	Claims jwt.MapClaims
	Hash   string
}

func VerifyIdentity(token []byte, jwksURL, tenantID string) (VerifiedIdentity, error) {
	claims, err := parseVerifiedToken(token, jwksURL)
	if err != nil {
		return VerifiedIdentity{}, err
	}

	if purpose, _ := claims["purpose"].(string); purpose == "delete" {
		return VerifiedIdentity{}, fmt.Errorf("delete token cannot be used for inference")
	}

	wantTenant := strings.TrimSpace(tenantID)
	if wantTenant != "" {
		got := tenantFromClaims(claims)
		if got != wantTenant {
			return VerifiedIdentity{}, fmt.Errorf("tenant_id mismatch: got %q want %q", got, wantTenant)
		}
	}

	hash, err := CommitmentHash(claims)
	if err != nil {
		return VerifiedIdentity{}, err
	}

	return VerifiedIdentity{Claims: claims, Hash: hash}, nil
}

func parseVerifiedToken(token []byte, jwksURL string) (jwt.MapClaims, error) {
	if len(token) == 0 {
		return nil, fmt.Errorf("missing identity token")
	}
	if strings.TrimSpace(jwksURL) == "" {
		return nil, fmt.Errorf("missing jwks url")
	}

	parsed, err := jwt.Parse(string(token), func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method %q", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("missing kid in jwt header")
		}
		return jwksCacheFor(jwksURL).key(kid)
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	if err != nil {
		return nil, fmt.Errorf("invalid jwt: %w", err)
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("invalid jwt")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid jwt claims")
	}
	return claims, nil
}
