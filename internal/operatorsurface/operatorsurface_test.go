package operatorsurface

import "testing"

// The public edge rewrites /v1/d/<endpoint>/X to /v1/X, so the surface answers on
// both the bare and the /v1-prefixed paths and must strip either prefix.
func TestScopeIDFromPath(t *testing.T) {
	cases := map[string]string{
		"/keyscope/ks1:abc":       "ks1:abc",
		"/v1/keyscope/ks1:abc":    "ks1:abc",
		"/keyscope/":              "",
		"/v1/keyscope/":           "",
		"/v1/keyscope/ks1:6fc332": "ks1:6fc332",
		"/keyscope/ks1:6fc332":    "ks1:6fc332",
		"/something-else":         "",
	}

	for path, want := range cases {
		if got := scopeIDFromPath(path); got != want {
			t.Errorf("scopeIDFromPath(%q) = %q, want %q", path, got, want)
		}
	}
}
