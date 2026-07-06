package memstore

import (
	"fmt"
	"sync"

	"nexqloud-sealed/internal/registry"
)

type Store struct {
	mu      sync.RWMutex
	records map[string]registry.CommitmentRecord
}

func New() *Store {
	return &Store{
		records: make(map[string]registry.CommitmentRecord),
	}
}

func (s *Store) Save(record registry.CommitmentRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.records[record.TenantID]
	if !ok {
		s.records[record.TenantID] = record
		return nil
	}

	if record.SeedCommit != "" && existing.SeedCommit != "" && record.SeedCommit != existing.SeedCommit {
		return fmt.Errorf("seed_commit mismatch for tenant %q", record.TenantID)
	}

	merged := existing
	if record.SeedCommit != "" {
		merged.SeedCommit = record.SeedCommit
	}
	if record.KeyVersion != 0 {
		merged.KeyVersion = record.KeyVersion
	}
	if merged.Wraps == nil {
		merged.Wraps = make(map[string][]byte)
	}
	for operatorID, wrap := range record.Wraps {
		merged.Wraps[operatorID] = wrap
	}

	s.records[record.TenantID] = merged
	return nil
}

func (s *Store) Get(tenantID string) (registry.CommitmentRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[tenantID]
	return record, ok
}
