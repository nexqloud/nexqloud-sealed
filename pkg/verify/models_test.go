package verify

import (
	"testing"

	"nexqloud-sealed/internal/modelattest"
)

func TestParseModelsAllowlistAndEffective(t *testing.T) {
	raw := []byte(`{
  "schema":"nexqloud-sealed-models-allowlist/1",
  "environment":"staging",
  "entries":[{"id":"qwen-0.5b","commitment":"sha256:abc"}]
}`)
	a, err := ParseModelsAllowlist(raw)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := FindModelCommitment(a, "qwen-0.5b")
	if !ok || c != "sha256:abc" {
		t.Fatalf("got %q ok=%v", c, ok)
	}
	eff := EffectiveModelCommitments([]string{"sha256:abc", "sha256:abc"})
	if len(eff) != 1 || eff[0] != "sha256:abc" {
		t.Fatalf("expected deduped published only, got %#v", eff)
	}
	if len(EffectiveModelCommitments(nil)) != 0 {
		t.Fatal("empty published should yield empty list")
	}
}

func TestCheckModelLegitRequiresCert(t *testing.T) {
	want := "sha256:74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
	nonce := "aabbccdd"
	cert := modelattest.NewCert(want, "qwen-0.5b", nonce, "nexqloud-model-attest-dev")
	signed, err := modelattest.SignCert(cert, modelattest.DevMockIssuerPriv)
	if err != nil {
		t.Fatal(err)
	}
	certMap, err := signed.ToMap()
	if err != nil {
		t.Fatal(err)
	}
	pkg := map[string]any{
		"model_commitment":      want,
		"model_commitment_cert": certMap,
		"nonce":                 nonce,
	}
	ok := checkModelLegit(pkg, VerifyOpts{
		Models:             []string{want},
		ModelAttestIssuers: []string{modelattest.DevMockIssuerPubkeyHex()},
	})
	if !ok.OK {
		t.Fatalf("expected OK, got %#v", ok)
	}

	failNoCert := checkModelLegit(map[string]any{"model_commitment": want, "nonce": nonce}, VerifyOpts{
		Models:             []string{want},
		ModelAttestIssuers: []string{modelattest.DevMockIssuerPubkeyHex()},
	})
	if failNoCert.OK {
		t.Fatal("expected fail without cert")
	}

	badNonce := map[string]any{
		"model_commitment":      want,
		"model_commitment_cert": certMap,
		"nonce":                 "deadbeef",
	}
	failNonce := checkModelLegit(badNonce, VerifyOpts{
		Models:             []string{want},
		ModelAttestIssuers: []string{modelattest.DevMockIssuerPubkeyHex()},
	})
	if failNonce.OK {
		t.Fatal("expected fail on nonce mismatch")
	}

	failIssuer := checkModelLegit(pkg, VerifyOpts{
		Models:             []string{want},
		ModelAttestIssuers: []string{"00"},
	})
	if failIssuer.OK {
		t.Fatal("expected fail on bad issuer")
	}
}

func TestCheckModelLegitMultiModelAllowlist(t *testing.T) {
	a := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	b := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	nonce := "11223344"
	cert := modelattest.NewCert(b, "model-b", nonce, "nexqloud-model-attest-dev")
	signed, err := modelattest.SignCert(cert, modelattest.DevMockIssuerPriv)
	if err != nil {
		t.Fatal(err)
	}
	certMap, err := signed.ToMap()
	if err != nil {
		t.Fatal(err)
	}
	pkg := map[string]any{
		"model_commitment":      b,
		"model_commitment_cert": certMap,
		"nonce":                 nonce,
	}
	ok := checkModelLegit(pkg, VerifyOpts{
		Models:             []string{a, b},
		ModelAttestIssuers: []string{modelattest.DevMockIssuerPubkeyHex()},
	})
	if !ok.OK {
		t.Fatalf("expected OK for second allowlisted model, got %#v", ok)
	}

	failWrong := checkModelLegit(pkg, VerifyOpts{
		Models:             []string{a},
		ModelAttestIssuers: []string{modelattest.DevMockIssuerPubkeyHex()},
	})
	if failWrong.OK {
		t.Fatal("expected fail when commitment not in allowlist")
	}
}

func TestCheckModelLegitCommitmentMismatch(t *testing.T) {
	want := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	nonce := "99"
	cert := modelattest.NewCert(want, "x", nonce, "dev")
	signed, err := modelattest.SignCert(cert, modelattest.DevMockIssuerPriv)
	if err != nil {
		t.Fatal(err)
	}
	certMap, err := signed.ToMap()
	if err != nil {
		t.Fatal(err)
	}
	pkg := map[string]any{
		"model_commitment":      "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		"model_commitment_cert": certMap,
		"nonce":                 nonce,
	}
	fail := checkModelLegit(pkg, VerifyOpts{
		Models:             []string{want, "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
		ModelAttestIssuers: []string{modelattest.DevMockIssuerPubkeyHex()},
	})
	if fail.OK {
		t.Fatal("expected fail on package vs cert commitment mismatch")
	}
}
