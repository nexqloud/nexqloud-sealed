package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"nexqloud-sealed/internal/gpu"
)

func TestCheckGPUWipedTwoPass(t *testing.T) {
	policyHash, err := gpu.Hash(gpu.DevReferencePolicy())
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	worker := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	nonce := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cert := gpu.ZeroizationCert{
		Schema:           gpu.CertSchema,
		ClearanceID:      "clr-1",
		GPUID:            "gpu-0",
		Method:           gpu.MethodTwoPass,
		PolicyHash:       policyHash,
		Nonce:            nonce,
		WorkerCommitment: worker,
		WipedAt:          time.Now().UTC().Format(time.RFC3339),
		Issuer:           "test-wipe",
	}
	signed, err := gpu.SignCert(cert, priv)
	if err != nil {
		t.Fatal(err)
	}
	m, err := gpu.CertToMap(signed)
	if err != nil {
		t.Fatal(err)
	}
	pkg := map[string]any{
		"gpu_policy_hash":  policyHash,
		"nonce":            nonce,
		"zeroization_cert": m,
	}
	opts := VerifyOpts{
		WipeIssuers: []string{hex.EncodeToString(pub)},
		WipeWorkers: []string{worker},
	}
	check := checkGPUWiped(pkg, opts)
	if !check.OK {
		t.Fatalf("expected ok, got %s", check.Detail)
	}
}

func TestCheckGPUWipedRejectsKVCacheClearedFalse(t *testing.T) {
	policyHash, err := gpu.Hash(gpu.DevReferencePolicy())
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	worker := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	nonce := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cert := gpu.ZeroizationCert{
		Schema:           gpu.CertSchema,
		ClearanceID:      "clr-2",
		GPUID:            "gpu-0",
		Method:           gpu.MethodTwoPass,
		PolicyHash:       policyHash,
		Nonce:            nonce,
		WorkerCommitment: worker,
		KVCacheCleared:   false,
		WipedAt:          time.Now().UTC().Format(time.RFC3339),
		Issuer:           "test-wipe",
	}
	signed, err := gpu.SignCert(cert, priv)
	if err != nil {
		t.Fatal(err)
	}
	m, err := gpu.CertToMap(signed)
	if err != nil {
		t.Fatal(err)
	}
	m["kv_cache_cleared"] = false
	pkg := map[string]any{
		"gpu_policy_hash":  policyHash,
		"nonce":            nonce,
		"zeroization_cert": m,
	}
	opts := VerifyOpts{
		WipeIssuers: []string{hex.EncodeToString(pub)},
		WipeWorkers: []string{worker},
	}
	check := checkGPUWiped(pkg, opts)
	if check.OK {
		t.Fatal("expected reject when kv_cache_cleared is false")
	}
	if check.Detail != "kv_cache_cleared is false" {
		t.Fatalf("detail=%q", check.Detail)
	}
}

func TestCheckGPUWipedKVClearedDetail(t *testing.T) {
	policyHash, err := gpu.Hash(gpu.DevReferencePolicy())
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	worker := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	nonce := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cert := gpu.ZeroizationCert{
		Schema:           gpu.CertSchema,
		ClearanceID:      "clr-3",
		GPUID:            "gpu-0",
		Method:           gpu.MethodTwoPass,
		PolicyHash:       policyHash,
		Nonce:            nonce,
		WorkerCommitment: worker,
		KVCacheCleared:   true,
		SlotsErased:      []int{0},
		WipedAt:          time.Now().UTC().Format(time.RFC3339),
		Issuer:           "test-wipe",
	}
	signed, err := gpu.SignCert(cert, priv)
	if err != nil {
		t.Fatal(err)
	}
	m, err := gpu.CertToMap(signed)
	if err != nil {
		t.Fatal(err)
	}
	pkg := map[string]any{
		"gpu_policy_hash":  policyHash,
		"nonce":            nonce,
		"zeroization_cert": m,
	}
	opts := VerifyOpts{
		WipeIssuers: []string{hex.EncodeToString(pub)},
		WipeWorkers: []string{worker},
	}
	check := checkGPUWiped(pkg, opts)
	if !check.OK {
		t.Fatalf("expected ok, got %s", check.Detail)
	}
	if !strings.Contains(check.Detail, "kv cleared (1 slots)") {
		t.Fatalf("detail=%q", check.Detail)
	}
}

func TestCheckGPUWipedRejectsDevNoop(t *testing.T) {
	t.Setenv("NEXQLOUD_DEV", "1")
	policyHash, err := gpu.Hash(gpu.DevReferencePolicy())
	if err != nil {
		t.Fatal(err)
	}
	m, err := gpu.RequestZeroization(policyHash, "aa")
	if err != nil {
		t.Fatal(err)
	}
	// RequestZeroization mock signs with DevMockIssuer — still MethodDevNoop
	pkg := map[string]any{
		"gpu_policy_hash":  policyHash,
		"nonce":            "aa",
		"zeroization_cert": m,
	}
	opts := VerifyOpts{
		WipeIssuers: []string{gpu.DevMockIssuerPubkeyHex()},
		WipeWorkers: []string{gpu.DevMockWorkerCommitment()},
	}
	check := checkGPUWiped(pkg, opts)
	if check.OK {
		t.Fatal("expected reject of dev-noop without AllowDevNoop")
	}
}
