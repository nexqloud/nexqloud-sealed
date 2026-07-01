package destruction

import (
	"testing"

	"nexqloud-sealed/internal/registry"
)

type mockRegistry struct {
	records map[string]registry.CommitmentRecord
}

func (m *mockRegistry) Get(tenantID string) (registry.CommitmentRecord, error) {
	rec, ok := m.records[tenantID]
	if !ok {
		return registry.CommitmentRecord{}, errNotFound{tenantID}
	}
	return rec, nil
}

type errNotFound struct{ tenant string }

func (e errNotFound) Error() string { return "record not found for tenant " + e.tenant }

func TestQuorum(t *testing.T) {
	reg := &mockRegistry{
		records: map[string]registry.CommitmentRecord{
			"acme": {
				TenantID: "acme",
				Wraps: map[string][]byte{
					"operator-b": {1},
					"operator-a": {2},
				},
			},
		},
	}

	ops, err := Quorum(reg, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 2 {
		t.Fatalf("len(ops) = %d", len(ops))
	}
	if ops[0] != "operator-a" || ops[1] != "operator-b" {
		t.Fatalf("ops = %v", ops)
	}
}

func TestQuorumNotFound(t *testing.T) {
	reg := &mockRegistry{records: map[string]registry.CommitmentRecord{}}
	_, err := Quorum(reg, "missing")
	if err == nil {
		t.Fatal("expected error")
	}
}
