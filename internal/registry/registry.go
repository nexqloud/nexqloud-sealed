package registry

import "sync"

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

func (s *Store) Save(record CommitmentRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[record.TenantID] = record
}

func (s *Store) Get(tenantID string) (CommitmentRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[tenantID]
	return record, ok
}
