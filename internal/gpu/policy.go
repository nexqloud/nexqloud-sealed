package gpu

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/gowebpki/jcs"

	"nexqloud-sealed/internal/devmode"
)

type Policy struct {
	PolicyVersion  string `json:"policy_version"`
	Persistence    string `json:"persistence"`
	NetworkEgress  string `json:"network_egress"`
	PayloadLogging string `json:"payload_logging"`
	Model          string `json:"model"`
}

func DefaultPolicy() Policy {
	model := strings.TrimSpace(os.Getenv("NEXQLOUD_MODEL_ID"))
	if model == "" && devmode.Enabled() {
		model = DevReferencePolicy().Model
	}
	return Policy{
		PolicyVersion:  "1",
		Persistence:    "disabled",
		NetworkEgress:  "deny",
		PayloadLogging: "disabled",
		Model:          model,
	}
}

func DevReferencePolicy() Policy {
	return Policy{
		PolicyVersion:  "1",
		Persistence:    "disabled",
		NetworkEgress:  "deny",
		PayloadLogging: "disabled",
		Model:          "mock-model",
	}
}

func Hash(p Policy) (string, error) {
	if p.Model == "" {
		return "", fmt.Errorf("gpu policy model is required (set NEXQLOUD_MODEL_ID or NEXQLOUD_DEV=1)")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshal policy: %w", err)
	}

	canonical, err := jcs.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("canonicalize policy: %w", err)
	}

	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func RequestZeroization() (map[string]any, error) {
	if !devmode.Enabled() {
		return nil, fmt.Errorf("gpu zeroization cert requires production worker integration (set NEXQLOUD_DEV=1 for mock cert)")
	}
	return map[string]any{
		"clearance_id": "mock-clearance-0001",
		"gpu_id":       "mock-gpu-0",
		"wiped_at":     "2026-06-24T00:00:00Z",
		"signature":    "mock-ed25519-signature-deadbeef",
		"issuer":       "mock-gpu-attestation-service",
	}, nil
}
