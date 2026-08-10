package wipe

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

const (
	ModeAuto       = "auto"
	ModeCUDA       = "cuda"
	ModeHostBuffer = "host-buffer"
	markerByte     = 0xA5
)

var gpuMu sync.Mutex

// TwoPass runs marker-then-zero wipe under a per-process GPU lock.
// WIPE_MODE: auto (cuda then fail), cuda, host-buffer (tests/CI only).
func TwoPass() error {
	gpuMu.Lock()
	defer gpuMu.Unlock()

	mode := strings.TrimSpace(os.Getenv("WIPE_MODE"))
	if mode == "" {
		mode = ModeAuto
	}
	switch mode {
	case ModeHostBuffer:
		return twoPassHostBuffer(64 << 20)
	case ModeCUDA:
		return twoPassCUDA()
	case ModeAuto:
		if err := twoPassCUDA(); err != nil {
			return fmt.Errorf("cuda wipe failed (set WIPE_MODE=host-buffer only for non-GPU tests): %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unknown WIPE_MODE %q", mode)
	}
}

func twoPassHostBuffer(n int) error {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = markerByte
	}
	for i := range buf {
		buf[i] = 0
	}
	_, _ = rand.Read(buf[:min(32, len(buf))])
	for i := range buf {
		buf[i] = 0
	}
	return nil
}

func twoPassCUDA() error {
	helper := strings.TrimSpace(os.Getenv("WIPE_CUDA_HELPER"))
	if helper == "" {
		if exe, err := os.Executable(); err == nil {
			cand := filepath.Join(filepath.Dir(exe), "vram_two_pass.py")
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				helper = cand
			}
		}
	}
	if helper == "" {
		helper = strings.TrimSpace(os.Getenv("WIPE_CUDA_HELPER_PATH"))
	}
	if helper == "" {
		// Repo-relative default when running from source tree.
		helper = "scripts/vram_two_pass.py"
	}
	if _, err := os.Stat(helper); err != nil {
		return fmt.Errorf("cuda helper not found at %s: %w", helper, err)
	}
	cmd := exec.Command("python3", helper)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("vram_two_pass: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
