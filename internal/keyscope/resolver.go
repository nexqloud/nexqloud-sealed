package keyscope

import (
	"errors"
	"fmt"

	"nexqloud-sealed/internal/derive/state"
	"nexqloud-sealed/internal/registry"
)

// ErrNoKeyMaterial means the scope's sealed key material is not available to this
// operator: either the scope was never registered here, or its wrap has been
// destroyed. Callers must treat it as terminal — a scope whose material is gone is
// meant to be unrecoverable, so it must never fall back to shared key material.
var ErrNoKeyMaterial = errors.New("no key material for scope")

// Resolver opens a scope's seed from the sealed copy this operator holds in the
// federation registry, using the same chip secret that sealed it.
type Resolver struct {
	Client     registry.Client
	OperatorID string
	Chip       func() ([]byte, error)
}

func (r *Resolver) Seed(tenantID string) ([]byte, error) {
	if !IsScope(tenantID) {
		return nil, fmt.Errorf("keyscope: %q is not a key scope", tenantID)
	}
	if r.Client == nil || r.OperatorID == "" || r.Chip == nil {
		return nil, fmt.Errorf("%w: resolver is not configured", ErrNoKeyMaterial)
	}

	record, err := r.Client.Get(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoKeyMaterial, err)
	}
	wrap, ok := record.Wraps[r.OperatorID]
	if !ok {
		return nil, fmt.Errorf("%w: operator %s holds no slot in %s", ErrNoKeyMaterial, r.OperatorID, tenantID)
	}
	if len(wrap) == 0 {
		return nil, fmt.Errorf("%w: slot for %s in %s was destroyed", ErrNoKeyMaterial, r.OperatorID, tenantID)
	}

	chipSecret, err := r.Chip()
	if err != nil {
		return nil, err
	}
	seed, err := state.Open(chipSecret, wrap)
	if err != nil {
		return nil, fmt.Errorf("%w: open wrap: %v", ErrNoKeyMaterial, err)
	}
	return seed, nil
}
