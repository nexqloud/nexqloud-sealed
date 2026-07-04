package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const HeaderNexQloudIdentity = "X-NexQloud-Identity"

type Commitment struct {
	Sub      string `json:"sub,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	Aud      string `json:"aud,omitempty"`
	Iat      int64  `json:"iat,omitempty"`
	Exp      int64  `json:"exp,omitempty"`
}

func CommitmentHash(claims jwt.MapClaims) (string, error) {
	c, err := commitmentFromClaims(claims)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("marshal identity commitment: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func commitmentFromClaims(claims jwt.MapClaims) (Commitment, error) {
	if claims == nil {
		return Commitment{}, fmt.Errorf("missing claims")
	}

	sub, _ := claims["sub"].(string)
	tenantID, _ := claims["tenant_id"].(string)
	if tenantID == "" {
		tenantID = sub
	}

	c := Commitment{
		Sub:      strings.TrimSpace(sub),
		TenantID: strings.TrimSpace(tenantID),
		Aud:      claimString(claims["aud"]),
	}
	if c.Sub == "" && c.TenantID == "" {
		return Commitment{}, fmt.Errorf("missing sub or tenant_id claim")
	}

	if v, ok := claims["iat"].(float64); ok {
		c.Iat = int64(v)
	}
	if v, ok := claims["exp"].(float64); ok {
		c.Exp = int64(v)
	}

	return c, nil
}

func claimString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}

func tenantFromClaims(claims jwt.MapClaims) string {
	if tenantID, _ := claims["tenant_id"].(string); tenantID != "" {
		return tenantID
	}
	if sub, _ := claims["sub"].(string); sub != "" {
		return sub
	}
	return ""
}
