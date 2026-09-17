package destruction

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nexqloud-sealed/internal/registry"
)

type stubRegistry struct {
	record registry.CommitmentRecord
}

func (s stubRegistry) Get(tenantID string) (registry.CommitmentRecord, error) {
	return s.record, nil
}

// A destruction is dispatched to the callback URL the operator registered with its
// wrap, so a deployment behind the public edge is reachable without editing the
// coordinator's operator map.
func TestDispatchPrefersRegisteredCallback(t *testing.T) {
	var hit string
	shim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = r.URL.Path
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"destroyed"}`))
	}))
	defer shim.Close()

	aggregator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer aggregator.Close()

	_, coordinatorSK, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate coordinator key: %v", err)
	}

	// Static map points somewhere else on purpose: the registered URL must win.
	c := NewCoordinator(stubRegistry{record: registry.CommitmentRecord{
		TenantID:  "acct-1",
		Wraps:     map[string][]byte{"operator-a": {1, 2, 3}},
		Callbacks: map[string]string{"operator-a": shim.URL},
	}}, aggregator.URL, map[string]string{"operator-a": "http://127.0.0.1:9"})
	c.CoordinatorSK = coordinatorSK

	session := Session{DestructionID: "d-1", TenantID: "acct-1", KeyVersion: 1, Quorum: []string{"operator-a"}}
	result := c.dispatchToOperator(context.Background(), session, "operator-a", []byte("customer-signature"))

	if hit == "" {
		t.Fatalf("operator was never called: %s", result.Detail)
	}
	if hit != "/destruction" {
		t.Fatalf("destruction dispatched to %q, want /destruction", hit)
	}
}

// Without a registered callback the configured operator map still applies, so
// standalone deployments keep working.
func TestDispatchFallsBackToOperatorMap(t *testing.T) {
	var hit string
	shim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = r.URL.Path
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"destroyed"}`))
	}))
	defer shim.Close()

	aggregator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer aggregator.Close()

	_, coordinatorSK, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate coordinator key: %v", err)
	}

	c := NewCoordinator(stubRegistry{record: registry.CommitmentRecord{
		TenantID: "acct-1",
		Wraps:    map[string][]byte{"operator-a": {1, 2, 3}},
	}}, aggregator.URL, map[string]string{"operator-a": shim.URL})
	c.CoordinatorSK = coordinatorSK

	session := Session{DestructionID: "d-2", TenantID: "acct-1", KeyVersion: 1, Quorum: []string{"operator-a"}}
	result := c.dispatchToOperator(context.Background(), session, "operator-a", []byte("customer-signature"))

	if hit == "" {
		t.Fatalf("operator was never called: %s", result.Detail)
	}
	if !strings.HasSuffix(hit, "/destruction") {
		t.Fatalf("destruction dispatched to %q, want a path ending in /destruction", hit)
	}
	var _ = json.Marshal
}
