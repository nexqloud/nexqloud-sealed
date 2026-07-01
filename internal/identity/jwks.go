package identity

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksCache struct {
	mu        sync.RWMutex
	url       string
	client    *http.Client
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
	ttl       time.Duration
}

func newJWKSCache(url string) *jwksCache {
	return &jwksCache{
		url:    url,
		client: http.DefaultClient,
		keys:   make(map[string]crypto.PublicKey),
		ttl:    5 * time.Minute,
	}
}

func (c *jwksCache) key(kid string) (crypto.PublicKey, error) {
	c.mu.RLock()
	if len(c.keys) > 0 && time.Since(c.fetchedAt) < c.ttl {
		key, ok := c.keys[kid]
		c.mu.RUnlock()
		if ok {
			return key, nil
		}
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	c.mu.RUnlock()

	if err := c.refresh(); err != nil {
		return nil, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok := c.keys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	return key, nil
}

func (c *jwksCache) refresh() error {
	resp, err := c.client.Get(c.url)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read jwks: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks %s: %s", resp.Status, string(body))
	}

	var parsed jwksResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}

	keys := make(map[string]crypto.PublicKey, len(parsed.Keys))
	for _, k := range parsed.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := rsaPublicKeyFromJWK(k.N, k.E)
		if err != nil {
			return err
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("jwks contains no usable RSA keys")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = keys
	c.fetchedAt = time.Now()
	return nil
}

func rsaPublicKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode jwk n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode jwk e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	var eInt int
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}
	if eInt == 0 {
		eInt = 65537
	}

	return &rsa.PublicKey{N: n, E: eInt}, nil
}
