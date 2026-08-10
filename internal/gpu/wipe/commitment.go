package wipe

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// SelfCommitment returns sha256 of this process executable, or WIPE_WORKER_COMMITMENT if set.
func SelfCommitment() (string, error) {
	if v := strings.TrimSpace(os.Getenv("WIPE_WORKER_COMMITMENT")); v != "" {
		if !strings.HasPrefix(v, "sha256:") {
			v = "sha256:" + v
		}
		return v, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("executable path: %w", err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return "", fmt.Errorf("read executable: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
