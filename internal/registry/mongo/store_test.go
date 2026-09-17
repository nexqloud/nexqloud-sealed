package mongo_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	registrymongo "nexqloud-sealed/internal/registry/mongo"
)

// newStore connects to the MongoDB in MONGO_URL, or skips. Tests get their own
// collection so they never touch real commitments.
func newStore(t *testing.T) (*registrymongo.Store, string) {
	t.Helper()

	uri := os.Getenv("MONGO_URL")
	if uri == "" {
		t.Skip("MONGO_URL is not set; skipping the MongoDB-backed registry test")
	}
	collection := fmt.Sprintf("commitments_test_%d", time.Now().UnixNano())

	ctx := context.Background()
	store, err := registrymongo.New(ctx, uri, "sealed_registry_test", collection)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = store.Close(cleanupCtx)
	})
	return store, collection
}

func tenant(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("ks1:test%d", time.Now().UnixNano())
}

func TestPutWrapRoundTrip(t *testing.T) {
	store, _ := newStore(t)
	id := tenant(t)

	if err := store.PutWrap(id, "operator-a", []byte("sealed-seed-a"), "sha256:commit"); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWrap(id, "operator-b", []byte("sealed-seed-b"), "sha256:commit"); err != nil {
		t.Fatal(err)
	}

	record, found, err := store.Get(id)
	if err != nil || !found {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if record.SeedCommit != "sha256:commit" {
		t.Fatalf("seed commit = %q", record.SeedCommit)
	}
	if string(record.Wraps["operator-a"]) != "sealed-seed-a" || string(record.Wraps["operator-b"]) != "sealed-seed-b" {
		t.Fatalf("unexpected wraps: %v", record.Wraps)
	}
}

func TestPutWrapRejectsConflictingSeedCommit(t *testing.T) {
	store, _ := newStore(t)
	id := tenant(t)

	if err := store.PutWrap(id, "operator-a", []byte("wrap-a"), "sha256:one"); err != nil {
		t.Fatal(err)
	}
	err := store.PutWrap(id, "operator-b", []byte("wrap-b"), "sha256:two")
	if !errors.Is(err, registrymongo.ErrSeedCommitConflict) {
		t.Fatalf("expected a seed_commit conflict, got %v", err)
	}
}

// A destroyed slot must keep its operator key: the destruction quorum is rebuilt
// from those keys, so dropping one would make the federation's proof unverifiable
// right after a successful erasure.
func TestDestroyWrapKeepsSlotAndIsIdempotent(t *testing.T) {
	store, _ := newStore(t)
	id := tenant(t)

	if err := store.PutWrap(id, "operator-a", []byte("wrap-a"), "sha256:commit"); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWrap(id, "operator-b", []byte("wrap-b"), "sha256:commit"); err != nil {
		t.Fatal(err)
	}

	destroyed, err := store.DestroyWrap(id, "operator-a")
	if err != nil || !destroyed {
		t.Fatalf("destroy: destroyed=%v err=%v", destroyed, err)
	}
	again, err := store.DestroyWrap(id, "operator-a")
	if err != nil {
		t.Fatal(err)
	}
	if again {
		t.Fatal("destroying twice must report nothing left to destroy")
	}

	record, found, err := store.Get(id)
	if err != nil || !found {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if len(record.Wraps) != 2 {
		t.Fatalf("operator slot was dropped: %v", record.Wraps)
	}
	if value, present := record.Wraps["operator-a"]; !present || len(value) != 0 {
		t.Fatalf("destroyed slot must be empty but present, got %v (present=%v)", value, present)
	}
	if string(record.Wraps["operator-b"]) != "wrap-b" {
		t.Fatal("operator-b material must be untouched")
	}
}

func TestGetUnknownTenant(t *testing.T) {
	store, _ := newStore(t)
	if _, found, err := store.Get(tenant(t)); err != nil || found {
		t.Fatalf("expected a missing record, got found=%v err=%v", found, err)
	}
}

func TestPutWrapValidatesInput(t *testing.T) {
	store, _ := newStore(t)
	id := tenant(t)

	if err := store.PutWrap(id, "operator-a", nil, "sha256:commit"); err == nil {
		t.Fatal("expected an error for an empty wrap")
	}
	if err := store.PutWrap(id, "bad.id", []byte("wrap"), "sha256:commit"); err == nil {
		t.Fatal("expected an error for an operator id that cannot be a field path")
	}
}
