package destruction

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"time"

	"nexqloud-sealed/internal/federation"
	"nexqloud-sealed/internal/receipt"
	"nexqloud-sealed/internal/tlog"
)

const (
	ExclusionMarkSchema = "sealed-exclusion-mark/1"
	exclusionReason     = "erased_by_exclusion"

	defaultMaxRetries = 5
	defaultBaseDelay  = time.Second
)

type Outcome string

const (
	OutcomeDestroyed         Outcome = "destroyed"
	OutcomeErasedByExclusion Outcome = "erased_by_exclusion"
)

type ExclusionMark struct {
	Schema     string `json:"schema"`
	OperatorID string `json:"operator_id"`
	TenantID   string `json:"tenant_id"`
	At         string `json:"at"`
	Reason     string `json:"reason"`
}

// Cryptographic erasure is not zero-latency media sanitization. Encrypted backups
// and replicas are not physically wiped; they become mathematically unreadable
// noise once the key material is destroyed. When an operator stays unreachable,
// exclusion removes their wrap slot from the qualified federation set and records
// that the slot was erased by exclusion rather than silently skipped.

type FailureHandler struct {
	MaxRetries int
	BaseDelay  time.Duration
	Signer     ed25519.PrivateKey
	Reach      func(ctx context.Context, opID, tenantID string) bool
}

func NewFailureHandler(signer ed25519.PrivateKey, reach func(ctx context.Context, opID, tenantID string) bool) *FailureHandler {
	return &FailureHandler{
		MaxRetries: defaultMaxRetries,
		BaseDelay:  defaultBaseDelay,
		Signer:     signer,
		Reach:      reach,
	}
}

func (h *FailureHandler) HandleUnreachable(ctx context.Context, opID, tenantID string) Outcome {
	if h.retryWithBackoff(ctx, opID, tenantID) {
		return OutcomeDestroyed
	}
	federation.Exclude(opID, tenantID)
	appendExclusionMark(h.Signer, ExclusionMark{
		Schema:     ExclusionMarkSchema,
		OperatorID: opID,
		TenantID:   tenantID,
		At:         nowRFC3339(),
		Reason:     exclusionReason,
	})
	return OutcomeErasedByExclusion
}

func (h *FailureHandler) retryWithBackoff(ctx context.Context, opID, tenantID string) bool {
	if h.Reach == nil {
		return false
	}
	delay := h.BaseDelay
	if delay <= 0 {
		delay = defaultBaseDelay
	}
	maxRetries := h.MaxRetries
	if maxRetries <= 0 {
		maxRetries = defaultMaxRetries
	}
	for attempt := 0; attempt < maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(delay):
		}
		if h.Reach(ctx, opID, tenantID) {
			return true
		}
		delay *= 2
	}
	return false
}

func appendExclusionMark(signer ed25519.PrivateKey, mark ExclusionMark) string {
	if len(signer) != ed25519.PrivateKeySize {
		return ""
	}
	pkg := map[string]any{
		"schema":      mark.Schema,
		"operator_id": mark.OperatorID,
		"tenant_id":   mark.TenantID,
		"at":          mark.At,
		"reason":      mark.Reason,
	}
	canonical, err := receipt.Canonicalize(pkg)
	if err != nil {
		return ""
	}
	sig := ed25519.Sign(signer, canonical)
	return tlog.AppendToLog(canonical, hex.EncodeToString(sig), signer)
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func isUnreachableDetail(detail string) bool {
	detail = strings.ToLower(detail)
	return strings.Contains(detail, "connection refused") ||
		strings.Contains(detail, "no such host") ||
		strings.Contains(detail, "i/o timeout") ||
		strings.Contains(detail, "context deadline exceeded") ||
		strings.Contains(detail, "connection reset") ||
		strings.Contains(detail, "network is unreachable") ||
		strings.Contains(detail, "dial tcp")
}
