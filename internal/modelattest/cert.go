package modelattest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"nexqloud-sealed/internal/signedclaim"
)

const CertSchema = "sealed-model-commitment/1"

// Cert is a nonce-bound signed statement that a model file hash was measured
// in the model VM (adjacent to llama).
type Cert struct {
	Schema          string `json:"schema"`
	ModelCommitment string `json:"model_commitment"`
	ModelID         string `json:"model_id,omitempty"`
	Nonce           string `json:"nonce"`
	AttestedAt      string `json:"attested_at"`
	Issuer          string `json:"issuer"`
	Pubkey          string `json:"pubkey"`
	Signature       string `json:"signature"`
}

func (c Cert) ToMap() (map[string]any, error) {
	return signedclaim.StructToMap(c)
}

func CertFromMap(raw map[string]any) (Cert, error) {
	var c Cert
	if err := signedclaim.MapToStruct(raw, &c); err != nil {
		return Cert{}, fmt.Errorf("parse model commitment cert: %w", err)
	}
	return c, nil
}

func SignCert(cert Cert, priv ed25519.PrivateKey) (Cert, error) {
	m, err := cert.ToMap()
	if err != nil {
		return Cert{}, err
	}
	if err := signedclaim.AttachSignature(m, priv); err != nil {
		return Cert{}, err
	}
	return CertFromMap(m)
}

func VerifyCertSignature(cert Cert) error {
	m, err := cert.ToMap()
	if err != nil {
		return err
	}
	return signedclaim.Verify(m, CertSchema)
}

// HashFile returns sha256:<hex> of the file at path.
func HashFile(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("model path is empty")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func NewCert(commitment, modelID, nonce, issuer string) Cert {
	return Cert{
		Schema:          CertSchema,
		ModelCommitment: strings.TrimSpace(commitment),
		ModelID:         strings.TrimSpace(modelID),
		Nonce:           strings.TrimSpace(nonce),
		AttestedAt:      time.Now().UTC().Format(time.RFC3339),
		Issuer:          strings.TrimSpace(issuer),
	}
}
