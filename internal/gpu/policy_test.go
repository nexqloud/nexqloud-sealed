package gpu

import (
	"testing"
)

func TestHashDeterministic(t *testing.T) {
	t.Setenv("NEXQLOUD_DEV", "1")
	p := DefaultPolicy()
	a, err := Hash(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Hash(p)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("expected deterministic hash, got %q and %q", a, b)
	}
	if len(a) != len("sha256:")+64 {
		t.Fatalf("unexpected hash format: %q", a)
	}
}

func TestRequestZeroizationMock(t *testing.T) {
	t.Setenv("NEXQLOUD_DEV", "1")
	cert, err := RequestZeroization()
	if err != nil {
		t.Fatal(err)
	}
	if cert["signature"] == nil {
		t.Fatal("expected mock signature in clearance certificate")
	}
}

func TestRequestZeroizationRequiresProdIntegration(t *testing.T) {
	t.Setenv("NEXQLOUD_DEV", "0")
	if _, err := RequestZeroization(); err == nil {
		t.Fatal("expected error without NEXQLOUD_DEV")
	}
}
