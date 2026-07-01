package destruction

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)

type PendingDestruction struct {
	DestructionID string
	TenantID      string
	Quorum        []string
	SeedCommit    string
	KeyVersion    int
	Receipts      map[string]Receipt
	Proof         *Proof
}

type Aggregator struct {
	SubstrateSK ed25519.PrivateKey

	mu       sync.RWMutex
	pending  map[string]*PendingDestruction
}

func NewAggregator(substrateSK ed25519.PrivateKey) *Aggregator {
	return &Aggregator{
		SubstrateSK: substrateSK,
		pending:     make(map[string]*PendingDestruction),
	}
}

type RegisterRequest struct {
	DestructionID string   `json:"destruction_id"`
	TenantID      string   `json:"tenant_id"`
	Quorum        []string `json:"quorum"`
	SeedCommit    string   `json:"seed_commit"`
	KeyVersion    int      `json:"key_version"`
}

func (a *Aggregator) Register(req RegisterRequest) error {
	if req.DestructionID == "" {
		return fmt.Errorf("destruction_id is required")
	}
	if len(req.Quorum) == 0 {
		return fmt.Errorf("quorum is required")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.pending[req.DestructionID]; exists {
		return fmt.Errorf("destruction %q already registered", req.DestructionID)
	}

	a.pending[req.DestructionID] = &PendingDestruction{
		DestructionID: req.DestructionID,
		TenantID:      req.TenantID,
		Quorum:        append([]string(nil), req.Quorum...),
		SeedCommit:    req.SeedCommit,
		KeyVersion:    req.KeyVersion,
		Receipts:      make(map[string]Receipt),
	}
	return nil
}

func (a *Aggregator) SubmitReceipt(destructionID string, receipt Receipt) (Proof, bool, error) {
	if err := VerifyReceipt(receipt); err != nil {
		return Proof{}, false, fmt.Errorf("invalid receipt: %w", err)
	}
	if receipt.DestructionID() != destructionID {
		return Proof{}, false, fmt.Errorf("destruction_id mismatch")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	p, ok := a.pending[destructionID]
	if !ok {
		return Proof{}, false, fmt.Errorf("destruction %q not registered", destructionID)
	}
	if p.Proof != nil {
		return *p.Proof, true, nil
	}

	opID := receipt.OperatorID()
	p.Receipts[opID] = receipt

	got := make([]Receipt, 0, len(p.Receipts))
	for _, r := range p.Receipts {
		got = append(got, r)
	}
	if len(got) < len(p.Quorum) {
		return Proof{}, false, nil
	}

	proof, err := a.aggregateLocked(p)
	if err != nil {
		return Proof{}, false, err
	}
	return proof, true, nil
}

func (a *Aggregator) Aggregate(destructionID string) (Proof, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	p, ok := a.pending[destructionID]
	if !ok {
		return Proof{}, fmt.Errorf("destruction %q not registered", destructionID)
	}
	if p.Proof != nil {
		return *p.Proof, nil
	}

	got := make([]Receipt, 0, len(p.Receipts))
	for _, r := range p.Receipts {
		got = append(got, r)
	}
	return a.aggregateFrom(p, got)
}

func (a *Aggregator) aggregateLocked(p *PendingDestruction) (Proof, error) {
	got := make([]Receipt, 0, len(p.Receipts))
	for _, r := range p.Receipts {
		got = append(got, r)
	}
	return a.aggregateFrom(p, got)
}

func (a *Aggregator) aggregateFrom(p *PendingDestruction, got []Receipt) (Proof, error) {
	proof, err := Aggregate(p.Quorum, got, p.DestructionID, a.SubstrateSK)
	if err != nil {
		return Proof{}, err
	}
	p.Proof = &proof
	return proof, nil
}

func (a *Aggregator) GetProof(destructionID string) (Proof, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	p, ok := a.pending[destructionID]
	if !ok || p.Proof == nil {
		return Proof{}, false
	}
	return *p.Proof, true
}

func (a *Aggregator) GetPending(destructionID string) (*PendingDestruction, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	p, ok := a.pending[destructionID]
	if !ok {
		return nil, false
	}
	copy := *p
	copy.Quorum = append([]string(nil), p.Quorum...)
	copy.Receipts = make(map[string]Receipt, len(p.Receipts))
	for k, v := range p.Receipts {
		copy.Receipts[k] = v
	}
	return &copy, true
}

func LoadSubstrateKey(hexSeed string) (ed25519.PrivateKey, error) {
	if hexSeed == "" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	seed, err := hex.DecodeString(hexSeed)
	if err != nil {
		return nil, fmt.Errorf("decode substrate-key-hex: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("substrate-key-hex length %d, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
