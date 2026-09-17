package keyscope_test

import (
	"errors"
	"testing"

	"nexqloud-sealed/internal/derive/state"
	"nexqloud-sealed/internal/keyscope"
	"nexqloud-sealed/internal/registry"
)

type fakeRegistry struct {
	record registry.CommitmentRecord
	err    error
}

func (f *fakeRegistry) Get(tenantID string) (registry.CommitmentRecord, error) {
	if f.err != nil {
		return registry.CommitmentRecord{}, f.err
	}
	return f.record, nil
}

// chip must be exactly 32 bytes: it is a ChaCha20-Poly1305 key.
func chip() ([]byte, error) {
	out := make([]byte, 32)
	copy(out, []byte("chip-secret-for-resolver-tests"))
	return out, nil
}

func scopeWithWrap(t *testing.T, seed []byte, operatorID string) *fakeRegistry {
	t.Helper()
	chipSecret, err := chip()
	if err != nil {
		t.Fatal(err)
	}
	return &fakeRegistry{record: registry.CommitmentRecord{
		TenantID:   "ks1:abc",
		SeedCommit: keyscope.SeedCommit(seed),
		Wraps:      map[string][]byte{operatorID: state.Seal(chipSecret, seed)},
	}}
}

func TestResolverOpensScopeSeedFromOwnWrap(t *testing.T) {
	seed := []byte("scope-seed-32-bytes-long!!!!!!!")
	reg := scopeWithWrap(t, seed, "operator-a")

	resolver := &keyscope.Resolver{Client: reg, OperatorID: "operator-a", Chip: chip}
	got, err := resolver.Seed("ks1:abc")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(seed) {
		t.Fatal("resolver returned the wrong scope seed")
	}
}

func TestResolverRefusesAfterDestruction(t *testing.T) {
	seed := []byte("scope-seed-32-bytes-long!!!!!!!")
	reg := scopeWithWrap(t, seed, "operator-a")
	// A destroyed slot is an empty wrap with the operator key retained.
	reg.record.Wraps["operator-a"] = nil

	resolver := &keyscope.Resolver{Client: reg, OperatorID: "operator-a", Chip: chip}
	_, err := resolver.Seed("ks1:abc")
	if !errors.Is(err, keyscope.ErrNoKeyMaterial) {
		t.Fatalf("expected ErrNoKeyMaterial after destruction, got %v", err)
	}
}

func TestResolverRefusesWithoutSlot(t *testing.T) {
	seed := []byte("scope-seed-32-bytes-long!!!!!!!")
	reg := scopeWithWrap(t, seed, "operator-a")

	resolver := &keyscope.Resolver{Client: reg, OperatorID: "operator-b", Chip: chip}
	if _, err := resolver.Seed("ks1:abc"); !errors.Is(err, keyscope.ErrNoKeyMaterial) {
		t.Fatalf("expected ErrNoKeyMaterial for a missing slot, got %v", err)
	}
}

func TestResolverRejectsNonScopeTenant(t *testing.T) {
	resolver := &keyscope.Resolver{Client: &fakeRegistry{}, OperatorID: "operator-a", Chip: chip}
	if _, err := resolver.Seed("acme"); err == nil {
		t.Fatal("expected the resolver to refuse a non-scope tenant")
	}
}

func TestResolverRejectsUnconfigured(t *testing.T) {
	resolver := &keyscope.Resolver{}
	if _, err := resolver.Seed("ks1:abc"); !errors.Is(err, keyscope.ErrNoKeyMaterial) {
		t.Fatalf("expected ErrNoKeyMaterial for an unconfigured resolver, got %v", err)
	}
}
