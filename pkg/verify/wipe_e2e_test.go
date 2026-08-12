package verify

import (
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"nexqloud-sealed/internal/gpu"
)

func TestWipeWorkerE2EHostBuffer(t *testing.T) {
	root := repoRoot(t)
	bin := filepath.Join(t.TempDir(), "wipe-worker")
	build := exec.Command("go", "build", "-o", bin, "./cmd/wipe-worker")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build wipe-worker: %v\n%s", err, out)
	}

	seed := []byte("e2e-wipe-issuer-seed-0123456789a") // 32 bytes
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed len %d", len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	privHex := hex.EncodeToString(seed)
	workerCommit := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	port := "19778"
	base := "http://127.0.0.1:" + port

	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		"WIPE_LISTEN=127.0.0.1:"+port,
		"WIPE_MODE=host-buffer",
		"WIPE_ISSUER_PRIVKEY="+privHex,
		"WIPE_WORKER_COMMITMENT="+workerCommit,
		"WIPE_ISSUER_ID=nexqloud-wipe-worker",
		"WIPE_KV_REQUIRED=0",
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get(base + "/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("wipe-worker did not become healthy")
		}
		time.Sleep(50 * time.Millisecond)
	}

	policyHash, err := gpu.Hash(gpu.DevReferencePolicy())
	if err != nil {
		t.Fatal(err)
	}
	nonce := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	t.Setenv("NEXQLOUD_WIPE_URL", base)
	t.Setenv("NEXQLOUD_DEV", "0")

	certMap, err := gpu.RequestZeroization(policyHash, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if certMap["method"] != gpu.MethodTwoPass {
		t.Fatalf("method=%v", certMap["method"])
	}

	pkg := map[string]any{
		"gpu_policy_hash":  policyHash,
		"nonce":            nonce,
		"zeroization_cert": certMap,
	}
	check := checkGPUWiped(pkg, VerifyOpts{
		WipeIssuers: []string{pubHex},
		WipeWorkers: []string{workerCommit},
	})
	if !check.OK {
		t.Fatalf("gpu_wiped: %s", check.Detail)
	}

	check = checkGPUWiped(pkg, VerifyOpts{
		WipeIssuers: []string{"00"},
		WipeWorkers: []string{workerCommit},
	})
	if check.OK {
		t.Fatal("expected issuer allowlist mismatch")
	}

	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	time.Sleep(50 * time.Millisecond)
	if _, err := gpu.RequestZeroization(policyHash, nonce); err == nil {
		t.Fatal("expected error when wipe worker is down")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd
		}
		wd = filepath.Dir(wd)
	}
	t.Fatal("go.mod not found")
	return ""
}
