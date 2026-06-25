package gpu

import "testing"

func TestHashDeterministic(t *testing.T) {
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
	cert := RequestZeroization()
	if cert["signature"] == nil {
		t.Fatal("expected mock signature in clearance certificate")
	}
}
