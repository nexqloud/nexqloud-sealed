package memstore_test

import (
	"testing"

	"nexqloud-sealed/demo/registry/memstore"
)

func TestPutWrapCreatesRecordAndMergesOperators(t *testing.T) {
	store := memstore.New()

	if err := store.PutWrap("ks1:abc", "operator-a", []byte("wrap-a"), "sha256:commit"); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWrap("ks1:abc", "operator-b", []byte("wrap-b"), "sha256:commit"); err != nil {
		t.Fatal(err)
	}

	record, ok := store.Get("ks1:abc")
	if !ok {
		t.Fatal("record was not created")
	}
	if record.SeedCommit != "sha256:commit" {
		t.Fatalf("seed commit = %q", record.SeedCommit)
	}
	if len(record.Wraps) != 2 || string(record.Wraps["operator-a"]) != "wrap-a" {
		t.Fatalf("unexpected wraps: %v", record.Wraps)
	}
}

func TestPutWrapRejectsConflictingSeedCommit(t *testing.T) {
	store := memstore.New()
	if err := store.PutWrap("ks1:abc", "operator-a", []byte("wrap-a"), "sha256:one"); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWrap("ks1:abc", "operator-b", []byte("wrap-b"), "sha256:two"); err == nil {
		t.Fatal("expected a seed_commit mismatch to be rejected")
	}
}

// The destruction quorum is reconstructed from the record's operator keys, so a
// destroyed slot must keep its key: dropping it would make the federation's proof
// unverifiable right after a successful erasure.
func TestDestroyWrapKeepsSlotSoQuorumSurvives(t *testing.T) {
	store := memstore.New()
	if err := store.PutWrap("ks1:abc", "operator-a", []byte("wrap-a"), "sha256:commit"); err != nil {
		t.Fatal(err)
	}
	if err := store.PutWrap("ks1:abc", "operator-b", []byte("wrap-b"), "sha256:commit"); err != nil {
		t.Fatal(err)
	}

	if !store.DestroyWrap("ks1:abc", "operator-a") {
		t.Fatal("expected the wrap to be reported as destroyed")
	}
	if store.DestroyWrap("ks1:abc", "operator-a") {
		t.Fatal("destroying twice must report nothing left to destroy")
	}

	record, _ := store.Get("ks1:abc")
	if len(record.Wraps) != 2 {
		t.Fatalf("operator slot was dropped: %v", record.Wraps)
	}
	if len(record.Wraps["operator-a"]) != 0 {
		t.Fatal("destroyed wrap still holds bytes")
	}
	if _, present := record.Wraps["operator-a"]; !present {
		t.Fatal("operator-a slot should remain as a tombstone")
	}
	if string(record.Wraps["operator-b"]) != "wrap-b" {
		t.Fatal("operator-b material must be untouched")
	}
}
