package gpu

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gowebpki/jcs"
)

const (
	CertSchema = "sealed-zeroization/1"

	// MethodTwoPass is the production wipe: overwrite VRAM buffers with
	// signed marker values, then overwrite the same regions with zeroes.
	MethodTwoPass = "two-pass-marker-zero"
	// MethodDevNoop marks a development certificate that performed no wipe.
	MethodDevNoop = "dev-noop"
)

// ZeroizationCert is the signed VRAM clearance issued by the GPU wipe worker
// after each inference response. Signature covers the JCS canonical form of
// the certificate with the signature field removed.
type ZeroizationCert struct {
	Schema      string `json:"schema"`
	ClearanceID string `json:"clearance_id"`
	GPUID       string `json:"gpu_id"`
	GPUModel    string `json:"gpu_model,omitempty"`
	Method      string `json:"method"`
	PolicyHash  string `json:"policy_hash"`
	Nonce       string `json:"nonce,omitempty"`
	WipedAt     string `json:"wiped_at"`
	Issuer      string `json:"issuer"`
	Pubkey      string `json:"pubkey"`
	Signature   string `json:"signature"`
}

func signingPayload(cert ZeroizationCert) ([]byte, error) {
	cert.Signature = ""
	raw, err := json.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("marshal zeroization cert: %w", err)
	}
	return jcs.Transform(raw)
}

// SignCert fills pubkey/signature on the certificate using the issuer key.
func SignCert(cert ZeroizationCert, priv ed25519.PrivateKey) (ZeroizationCert, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return ZeroizationCert{}, fmt.Errorf("invalid issuer private key")
	}
	cert.Pubkey = hex.EncodeToString(pub)
	payload, err := signingPayload(cert)
	if err != nil {
		return ZeroizationCert{}, err
	}
	cert.Signature = hex.EncodeToString(ed25519.Sign(priv, payload))
	return cert, nil
}

// VerifyCertSignature checks that the certificate signature verifies under
// the pubkey embedded in the certificate. Issuer trust is decided separately.
func VerifyCertSignature(cert ZeroizationCert) error {
	if cert.Schema != CertSchema {
		return fmt.Errorf("unsupported zeroization cert schema %q", cert.Schema)
	}
	pub, err := hex.DecodeString(cert.Pubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid zeroization cert pubkey")
	}
	sig, err := hex.DecodeString(cert.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid zeroization cert signature encoding")
	}
	payload, err := signingPayload(cert)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return fmt.Errorf("zeroization cert signature verification failed")
	}
	return nil
}

// CertFromMap parses the zeroization_cert package field.
func CertFromMap(raw map[string]any) (ZeroizationCert, error) {
	data, err := json.Marshal(raw)
	if err != nil {
		return ZeroizationCert{}, fmt.Errorf("marshal zeroization cert: %w", err)
	}
	var cert ZeroizationCert
	if err := json.Unmarshal(data, &cert); err != nil {
		return ZeroizationCert{}, fmt.Errorf("parse zeroization cert: %w", err)
	}
	return cert, nil
}

// CertToMap renders the certificate for embedding in the receipt package.
func CertToMap(cert ZeroizationCert) (map[string]any, error) {
	data, err := json.Marshal(cert)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateCertTimestamp checks wiped_at parses and is not in the future
// beyond the allowed clock skew.
func ValidateCertTimestamp(cert ZeroizationCert, now time.Time, skew time.Duration) error {
	wiped, err := time.Parse(time.RFC3339, cert.WipedAt)
	if err != nil {
		return fmt.Errorf("invalid wiped_at timestamp: %v", err)
	}
	if wiped.After(now.Add(skew)) {
		return fmt.Errorf("wiped_at is in the future")
	}
	return nil
}
