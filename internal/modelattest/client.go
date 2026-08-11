package modelattest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"nexqloud-sealed/internal/devmode"
)

const defaultTimeout = 60 * time.Second

// DevMockIssuerPriv is a fixed test key (not for production).
var DevMockIssuerPriv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32))

func DevMockIssuerPubkeyHex() string {
	return hex.EncodeToString(DevMockIssuerPriv.Public().(ed25519.PublicKey))
}

type attestRequest struct {
	Nonce string `json:"nonce"`
}

// RequestCommitment asks the model-attest service for a signed claim.
// When NEXQLOUD_MODEL_ATTEST_URL is set, dials that service.
// When unset and NEXQLOUD_DEV=1, returns a mock cert for unit tests.
func RequestCommitment(nonce string) (commitment string, certMap map[string]any, err error) {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return "", nil, fmt.Errorf("nonce required for model attestation")
	}

	base := strings.TrimRight(strings.TrimSpace(os.Getenv("NEXQLOUD_MODEL_ATTEST_URL")), "/")
	if base != "" {
		return requestCommitmentHTTP(base, nonce)
	}
	if !devmode.Enabled() {
		return "", nil, fmt.Errorf("NEXQLOUD_MODEL_ATTEST_URL is required (set NEXQLOUD_DEV=1 for mock cert)")
	}
	return mockCommitment(nonce)
}

func requestCommitmentHTTP(base, nonce string) (string, map[string]any, error) {
	body, err := json.Marshal(attestRequest{Nonce: nonce})
	if err != nil {
		return "", nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	url := base + "/v1/attest-model"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("model-attest %s: %w", url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", nil, fmt.Errorf("read model-attest response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", nil, fmt.Errorf("model-attest %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", nil, fmt.Errorf("parse model-attest cert: %w", err)
	}
	cert, err := CertFromMap(out)
	if err != nil {
		return "", nil, err
	}
	if err := VerifyCertSignature(cert); err != nil {
		return "", nil, fmt.Errorf("model-attest returned invalid cert: %w", err)
	}
	if cert.Nonce != nonce {
		return "", nil, fmt.Errorf("model-attest nonce mismatch")
	}
	if cert.ModelCommitment == "" {
		return "", nil, fmt.Errorf("model-attest cert missing model_commitment")
	}
	return cert.ModelCommitment, out, nil
}

func mockCommitment(nonce string) (string, map[string]any, error) {
	commit := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if v := strings.TrimSpace(os.Getenv("NEXQLOUD_MODEL_COMMIT")); v != "" {
		commit = v
	}
	cert := NewCert(commit, envOr("NEXQLOUD_MODEL_ID", "mock-model"), nonce, "nexqloud-model-attest-dev")
	signed, err := SignCert(cert, DevMockIssuerPriv)
	if err != nil {
		return "", nil, err
	}
	m, err := signed.ToMap()
	if err != nil {
		return "", nil, err
	}
	return commit, m, nil
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
