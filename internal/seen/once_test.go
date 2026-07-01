package seen_test

import (
	"testing"

	"nexqloud-sealed/internal/seen"
)

func TestOnceAcceptsFirstUse(t *testing.T) {
	seen.Reset()
	if err := seen.Once("nonce-1"); err != nil {
		t.Fatal(err)
	}
}

func TestOnceRejectsReplay(t *testing.T) {
	seen.Reset()
	_ = seen.Once("nonce-2")
	err := seen.Once("nonce-2")
	if err == nil {
		t.Fatal("expected replay error")
	}
}
