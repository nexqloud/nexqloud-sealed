package registry

import (
	"fmt"
	"sync"
)

type CommitmentRecord struct {
	TenantID   string            `json:"tenant_id"`
	KeyVersion int               `json:"key_version"`
	SeedCommit string            `json:"seed_commit"`
	Wraps      map[string][]byte `json:"wraps"`
}

type Store struct {
	mu      sync.RWMutex
	records map[string]CommitmentRecord
}

func NewStore() *Store {
	return &Store{
		records: make(map[string]CommitmentRecord),
	}
}

func (s *Store) Save(record CommitmentRecord) error {
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

func (s *Store) Get(tenantID string) (CommitmentRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[tenantID]
	return record, ok
}
