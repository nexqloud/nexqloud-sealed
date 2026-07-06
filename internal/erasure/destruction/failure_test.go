package destruction

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync/atomic"
	"testing"
	"time"

	"nexqloud-sealed/internal/federation"
)

func TestFailureHandlerRetrySucceeds(t *testing.T) {
	t.Cleanup(federation.Reset)

	var attempts atomic.Int32
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	handler := NewFailureHandler(priv, func(ctx context.Context, opID, tenantID string) bool {
		n := attempts.Add(1)
		return n >= 3
	})
	handler.BaseDelay = time.Millisecond
	handler.MaxRetries = 5

	outcome := handler.HandleUnreachable(t.Context(), "operator-a", "acme")
	if outcome != OutcomeDestroyed {
		t.Fatalf("outcome = %q", outcome)
	}
	if attempts.Load() < 3 {
		t.Fatalf("attempts = %d", attempts.Load())
	}
	if federation.IsExcluded("operator-a", "acme") {
		t.Fatal("operator should not be excluded after successful retry")
	}
}

func TestFailureHandlerExclusion(t *testing.T) {
	t.Cleanup(federation.Reset)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	handler := NewFailureHandler(priv, func(ctx context.Context, opID, tenantID string) bool {
		return false
	})
	handler.BaseDelay = time.Millisecond
	handler.MaxRetries = 2

	outcome := handler.HandleUnreachable(t.Context(), "operator-b", "acme")
	if outcome != OutcomeErasedByExclusion {
		t.Fatalf("outcome = %q", outcome)
	}
	if !federation.IsExcluded("operator-b", "acme") {
		t.Fatal("operator should be excluded")
	}
}

func TestIsUnreachableDetail(t *testing.T) {
	if !isUnreachableDetail("Post \"http://127.0.0.1:9/destruction\": dial tcp 127.0.0.1:9: connect: connection refused") {
		t.Fatal("expected connection refused to be unreachable")
	}
	if isUnreachableDetail("400 Bad Request: invalid signature") {
		t.Fatal("expected application error not to be unreachable")
	}
}
