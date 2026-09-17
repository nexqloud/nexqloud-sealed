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

// PutWrap registers one operator's wrap for a tenant, creating a minimal record
// when the key scope does not exist yet.
func (s *Store) PutWrap(tenantID, operatorID string, wrap []byte, seedCommit string) error {
	if tenantID == "" || operatorID == "" {
		return fmt.Errorf("tenant_id and operator_id are required")
	}
	if len(wrap) == 0 {
		return fmt.Errorf("wrap is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[tenantID]
	if !ok {
		record = registry.CommitmentRecord{
			TenantID: tenantID,
			Wraps:    make(map[string][]byte),
		}
	}
	if record.SeedCommit != "" && seedCommit != "" && record.SeedCommit != seedCommit {
		return fmt.Errorf("seed_commit mismatch for tenant %q", tenantID)
	}
	if record.SeedCommit == "" && seedCommit != "" {
		record.SeedCommit = seedCommit
	}
	if record.Wraps == nil {
		record.Wraps = make(map[string][]byte)
	}
	record.Wraps[operatorID] = append([]byte(nil), wrap...)

	s.records[tenantID] = record
	return nil
}

// PutCallback records how a coordinator can reach one operator node for this scope.
func (s *Store) PutCallback(tenantID, operatorID, callbackURL string) error {
	if tenantID == "" || operatorID == "" {
		return fmt.Errorf("tenant_id and operator_id are required")
	}
	if callbackURL == "" {
		return fmt.Errorf("callback url is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[tenantID]
	if !ok {
		return fmt.Errorf("record not found for tenant %q", tenantID)
	}
	if record.Callbacks == nil {
		record.Callbacks = make(map[string]string)
	}
	record.Callbacks[operatorID] = callbackURL

	s.records[tenantID] = record
	return nil
}

// DestroyWrap zeroes one operator's wrap while keeping its slot in the record.
//
// Keeping the slot matters twice over: a later derivation can tell "destroyed"
// apart from "never registered" (empty wrap vs missing operator), and the
// verifier can still reconstruct the destruction quorum from the registry, which
// is exactly the "every operator that ever held material" property the protocol
// depends on. Reports whether material was actually present.
func (s *Store) DestroyWrap(tenantID, operatorID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.records[tenantID]
	if !ok || record.Wraps == nil {
		return false
	}
	wrap, exists := record.Wraps[operatorID]
	if !exists || len(wrap) == 0 {
		return false
	}
	for i := range wrap {
		wrap[i] = 0
	}
	record.Wraps[operatorID] = nil
	s.records[tenantID] = record
	return true
}

func (s *Store) Get(tenantID string) (registry.CommitmentRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[tenantID]
	return record, ok
}
