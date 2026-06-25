package model

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCommitment(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "b.safetensors"), []byte("beta"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.safetensors"), []byte("alpha"), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := Commitment(dir)
	if err != nil {
		t.Fatalf("Commitment: %v", err)
	}

	want, err := Commitment(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("expected deterministic commitment %q, got %q", want, got)
	}
	if len(got) != len("sha256:")+64 {
		t.Fatalf("expected sha256: + 64 hex chars, got %q", got)
	}
}
