package federation

import "testing"

func TestExcludeAndFilter(t *testing.T) {
	t.Cleanup(Reset)

	ops := []string{"operator-a", "operator-b", "operator-c"}
	Exclude("operator-b", "acme")

	if !IsExcluded("operator-b", "acme") {
		t.Fatal("expected operator-b excluded")
	}
	if IsExcluded("operator-a", "acme") {
		t.Fatal("operator-a should not be excluded")
	}

	filtered := FilterQualified(ops, "acme")
	if len(filtered) != 2 {
		t.Fatalf("filtered = %v", filtered)
	}
	if filtered[0] != "operator-a" || filtered[1] != "operator-c" {
		t.Fatalf("filtered = %v", filtered)
	}
}
