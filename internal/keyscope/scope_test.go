package keyscope_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"nexqloud-sealed/internal/keyscope"
)

func TestIDIsDeterministicAndScopeScoped(t *testing.T) {
	a, err := keyscope.ID("acct-1", "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	again, err := keyscope.ID("acct-1", "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	if a != again {
		t.Fatalf("scope id is not deterministic: %q vs %q", a, again)
	}
	if !keyscope.IsScope(a) {
		t.Fatalf("scope id %q is not recognised as a scope", a)
	}

	other, err := keyscope.ID("acct-1", "sess-2")
	if err != nil {
		t.Fatal(err)
	}
	if other == a {
		t.Fatal("two conversations resolved to the same scope")
	}
	otherAccount, err := keyscope.ID("acct-2", "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	if otherAccount == a {
		t.Fatal("two accounts resolved to the same scope")
	}
	if keyscope.IsScope("acme") {
		t.Fatal("a plain tenant must not be treated as a scope")
	}
}

func TestScopeIDVectorMatchesPlatformImplementations(t *testing.T) {
	// These vectors are shared with the dcp gateway
	// (gateway-service/src/sealed/sealed-scope.ts). If one side changes the
	// derivation, the gateway would mint tokens for a scope the operators never
	// sealed, and erasure would look like it worked while the data stayed readable.
	cases := map[string]string{
		"acct-1|sess-1":   "ks1:b49d6f2c160a5fbb325223d5fb8ded26",
		"acct-me|conv-42": "ks1:b60aaaf72e31a65a74781ae4696051fb",
	}
	for input, want := range cases {
		account, session, _ := strings.Cut(input, "|")
		got, err := keyscope.ID(account, session)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("scope id for %q = %q, want %q", input, got, want)
		}
	}
}

func TestIDRequiresBothIDs(t *testing.T) {
	if _, err := keyscope.ID("", "sess-1"); err == nil {
		t.Fatal("expected error for missing account id")
	}
	if _, err := keyscope.ID("acct-1", "  "); err == nil {
		t.Fatal("expected error for missing session id")
	}
}

func TestSeedRoundTripAndCommit(t *testing.T) {
	seed, err := keyscope.NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != keyscope.SeedSize {
		t.Fatalf("seed length %d, want %d", len(seed), keyscope.SeedSize)
	}
	other, err := keyscope.NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(seed, other) {
		t.Fatal("two generated seeds are identical")
	}

	commit := keyscope.SeedCommit(seed)
	if !strings.HasPrefix(commit, "sha256:") {
		t.Fatalf("unexpected commit %q", commit)
	}
	if keyscope.SeedCommit(other) == commit {
		t.Fatal("different seeds produced the same commit")
	}

	parsed, err := keyscope.ParseSeed(hex.EncodeToString(seed))
	if err != nil {
		t.Fatalf("a generated seed should round-trip through hex: %v", err)
	}
	if !bytes.Equal(parsed, seed) {
		t.Fatal("parsed seed does not match")
	}

	if _, err := keyscope.ParseSeed("not-hex"); err == nil {
		t.Fatal("expected error for non-hex seed")
	}
	if _, err := keyscope.ParseSeed("0011"); err == nil {
		t.Fatal("expected error for short seed")
	}
}
