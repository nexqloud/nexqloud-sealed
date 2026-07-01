package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type LocalStore struct {
	OperatorID string
	Client     Client
	Dir        string

	mu    sync.Mutex
	cache map[string][]byte
}

func NewLocalStore(operatorID string, client Client, dir string) *LocalStore {
	return &LocalStore{
		OperatorID: operatorID,
		Client:     client,
		Dir:        dir,
		cache:      make(map[string][]byte),
	}
}

var defaultLocal *LocalStore

func ConfigureLocal(store *LocalStore) {
	defaultLocal = store
}

func LocalWrap(tenantID string) ([]byte, error) {
	if defaultLocal == nil {
		return nil, fmt.Errorf("local wrap store not configured")
	}
	return defaultLocal.LocalWrap(tenantID)
}

func (s *LocalStore) LocalWrap(tenantID string) ([]byte, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if wrap, ok := s.cache[tenantID]; ok {
		return cloneBytes(wrap), nil
	}

	if s.Dir != "" {
		path := filepath.Join(s.Dir, tenantID+".wrap")
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			s.cache[tenantID] = cloneBytes(data)
			return cloneBytes(data), nil
		}
	}

	rec, err := s.Client.Get(tenantID)
	if err != nil {
		return nil, err
	}
	wrap, ok := rec.Wraps[s.OperatorID]
	if !ok {
		return nil, fmt.Errorf("wrap for operator %q not found", s.OperatorID)
	}

	s.cache[tenantID] = cloneBytes(wrap)
	if s.Dir != "" {
		path := filepath.Join(s.Dir, tenantID+".wrap")
		_ = os.MkdirAll(s.Dir, 0o700)
		_ = os.WriteFile(path, wrap, 0o600)
	}
	return cloneBytes(wrap), nil
}

func (s *LocalStore) OverwriteWrap(tenantID string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cache[tenantID] = cloneBytes(data)
	if s.Dir == "" {
		return nil
	}
	path := filepath.Join(s.Dir, tenantID+".wrap")
	return os.WriteFile(path, data, 0o600)
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
