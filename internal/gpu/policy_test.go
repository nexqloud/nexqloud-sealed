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
	t.Setenv("NEXQLOUD_WIPE_URL", "")
	h, err := Hash(DevReferencePolicy())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := RequestZeroization(h, "aabb")
	if err != nil {
		t.Fatal(err)
	}
	if cert["signature"] == nil {
		t.Fatal("expected mock signature in clearance certificate")
	}
	if cert["method"] != MethodDevNoop {
		t.Fatalf("expected %s, got %v", MethodDevNoop, cert["method"])
	}
}

func TestRequestZeroizationRequiresWipeURL(t *testing.T) {
	t.Setenv("NEXQLOUD_DEV", "0")
	t.Setenv("NEXQLOUD_WIPE_URL", "")
	if _, err := RequestZeroization("sha256:00", "aa"); err == nil {
		t.Fatal("expected error without wipe URL")
	}
}
