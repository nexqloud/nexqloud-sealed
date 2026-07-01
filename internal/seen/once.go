package seen

import (
	"fmt"
	"sync"
)

var defaultStore = NewStore()

type Store struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func NewStore() *Store {
	return &Store{seen: make(map[string]struct{})}
}

func Once(nonce string) error {
	return defaultStore.Once(nonce)
}

func (s *Store) Once(nonce string) error {
	if nonce == "" {
		return fmt.Errorf("empty nonce")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[nonce]; ok {
		return fmt.Errorf("replay detected: nonce already used")
	}
	s.seen[nonce] = struct{}{}
	return nil
}

func Reset() {
	defaultStore = NewStore()
}

func (s *Store) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = make(map[string]struct{})
}
