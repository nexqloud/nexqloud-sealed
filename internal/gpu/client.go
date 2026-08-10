package gpu

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"nexqloud-sealed/internal/devmode"
)

const defaultWipeTimeout = 60 * time.Second

type zeroizeRequest struct {
	Nonce      string `json:"nonce"`
	PolicyHash string `json:"policy_hash"`
	GPUID      string `json:"gpu_id,omitempty"`
}

// RequestZeroization asks the host wipe worker for a signed clearance cert.
// When NEXQLOUD_WIPE_URL is set, always dials the worker.
// When unset and NEXQLOUD_DEV=1, returns a MethodDevNoop mock for unit tests.
func RequestZeroization(policyHash, nonce string) (map[string]any, error) {
	policyHash = strings.TrimSpace(policyHash)
	nonce = strings.TrimSpace(nonce)
	if policyHash == "" {
		return nil, fmt.Errorf("policy_hash required for zeroization")
	}

	base := strings.TrimRight(strings.TrimSpace(os.Getenv("NEXQLOUD_WIPE_URL")), "/")
	if base != "" {
		return requestZeroizationHTTP(base, policyHash, nonce)
	}
	if !devmode.Enabled() {
		return nil, fmt.Errorf("NEXQLOUD_WIPE_URL is required for GPU zeroization (set NEXQLOUD_DEV=1 for mock cert)")
	}
	return mockZeroizationCert(policyHash, nonce)
}

func requestZeroizationHTTP(base, policyHash, nonce string) (map[string]any, error) {
	body, err := json.Marshal(zeroizeRequest{
		Nonce:      nonce,
		PolicyHash: policyHash,
		GPUID:      strings.TrimSpace(os.Getenv("NEXQLOUD_GPU_ID")),
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultWipeTimeout)
	defer cancel()

	url := base + "/v1/zeroize"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wipe worker %s: %w", url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read wipe response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("wipe worker %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse wipe cert: %w", err)
	}
	if out["signature"] == nil || out["signature"] == "" {
		return nil, fmt.Errorf("wipe worker returned cert without signature")
	}
	return out, nil
}
