package verify

import "testing"

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
	eff := EffectiveModelCommitments([]string{"sha256:abc"})
	if len(eff) < 2 {
		t.Fatalf("expected published + mock catalog, got %#v", eff)
	}
	foundMock := false
	for _, x := range eff {
		if x == ModelCatalog["mock-model"] {
			foundMock = true
		}
	}
	if !foundMock {
		t.Fatal("mock catalog missing from effective list")
	}
}

func TestCheckModelLegitUsesOpts(t *testing.T) {
	want := "sha256:74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
	pkg := map[string]any{"model_commitment": want}
	ok := checkModelLegit(pkg, VerifyOpts{Models: []string{want}})
	if !ok.OK {
		t.Fatalf("expected OK, got %#v", ok)
	}
	fail := checkModelLegit(pkg, VerifyOpts{})
	if fail.OK {
		t.Fatal("expected fail without allowlist")
	}
}