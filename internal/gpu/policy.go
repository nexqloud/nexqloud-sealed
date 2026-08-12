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
	PromptCache    string `json:"prompt_cache"`
	KVCacheClear   string `json:"kv_cache_clear"`
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
		PromptCache:    "disabled",
		KVCacheClear:   "per-response",
		Model:          model,
	}
}

func DevReferencePolicy() Policy {
	return Policy{
		PolicyVersion:  "1",
		Persistence:    "disabled",
		NetworkEgress:  "deny",
		PayloadLogging: "disabled",
		PromptCache:    "disabled",
		KVCacheClear:   "per-response",
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
