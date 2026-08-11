// Package signedclaim provides JCS + ed25519 signing for sealed evidence claims.
// Model attestation uses this now; GPU wipe can migrate onto it later.
package signedclaim

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gowebpki/jcs"
)

// Payload returns the JCS canonical form of claim with signature cleared.
func Payload(claim map[string]any) ([]byte, error) {
	if claim == nil {
		return nil, fmt.Errorf("signedclaim: nil claim")
	}
	cp := make(map[string]any, len(claim))
	for k, v := range claim {
		if k == "signature" {
			continue
		}
		cp[k] = v
	}
	raw, err := json.Marshal(cp)
	if err != nil {
		return nil, fmt.Errorf("signedclaim: marshal: %w", err)
	}
	return jcs.Transform(raw)
}

// AttachSignature sets pubkey and signature on claim using priv.
func AttachSignature(claim map[string]any, priv ed25519.PrivateKey) error {
	if claim == nil {
		return fmt.Errorf("signedclaim: nil claim")
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("signedclaim: invalid private key")
	}
	claim["pubkey"] = hex.EncodeToString(pub)
	delete(claim, "signature")
	payload, err := Payload(claim)
	if err != nil {
		return err
	}
	claim["signature"] = hex.EncodeToString(ed25519.Sign(priv, payload))
	return nil
}

// Verify checks schema (if expectedSchema non-empty), pubkey, and ed25519 signature.
func Verify(claim map[string]any, expectedSchema string) error {
	if claim == nil {
		return fmt.Errorf("signedclaim: nil claim")
	}
	if expectedSchema != "" {
		schema, _ := claim["schema"].(string)
		if schema != expectedSchema {
			return fmt.Errorf("signedclaim: unsupported schema %q", schema)
		}
	}
	pubHex, _ := claim["pubkey"].(string)
	sigHex, _ := claim["signature"].(string)
	pub, err := hex.DecodeString(strings.TrimSpace(pubHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("signedclaim: invalid pubkey")
	}
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signedclaim: invalid signature encoding")
	}
	payload, err := Payload(claim)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return fmt.Errorf("signedclaim: signature verification failed")
	}
	return nil
}

// StructToMap round-trips a claim struct to a generic map.
func StructToMap(v any) (map[string]any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// MapToStruct decodes a claim map into dest.
func MapToStruct(raw map[string]any, dest any) error {
	data, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dest)
}
