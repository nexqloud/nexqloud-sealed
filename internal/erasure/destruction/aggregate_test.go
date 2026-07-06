package destruction

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSameSet(t *testing.T) {
	if !sameSet([]string{"a", "b"}, []string{"b", "a"}) {
		t.Fatal("expected same set")
	}
	if sameSet([]string{"a"}, []string{"a", "b"}) {
		t.Fatal("expected different set")
	}
}

func TestAggregateIncompleteQuorum(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"operator-a", "operator-b"}
	got := []Receipt{}
	_, err = Aggregate(want, got, "dest-1", priv)
	if err == nil || err.Error() != "incomplete quorum: data would remain recoverable" {
		t.Fatalf("err = %v", err)
	}

	r1, err := NewTestReceipt(priv, "dest-1", "operator-a", "sha256:aa", "sha256:bb", 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Aggregate(want, []Receipt{r1}, "dest-1", priv)
	if err == nil || err.Error() != "incomplete quorum: data would remain recoverable" {
		t.Fatalf("err = %v", err)
	}
}

func TestAggregateCompleteQuorum(t *testing.T) {
	_, opAPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, opBPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, substrateSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tenantHash := "sha256:822b33ad87c148a0a20a5ba7cd5ebcaa68d36a18e7aad165554903f52ca82757"
	seedCommit := "sha256:908d6b75eaf8eff5dd727ec79e6c118a0933bbf97a60ffd7581ea4a7075b64f5"

	rA, err := NewTestReceipt(opAPriv, "dest-1", "operator-a", tenantHash, seedCommit, 1)
	if err != nil {
		t.Fatal(err)
	}
	rB, err := NewTestReceipt(opBPriv, "dest-1", "operator-b", tenantHash, seedCommit, 1)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"operator-a", "operator-b"}
	proof, err := Aggregate(want, []Receipt{rA, rB}, "dest-1", substrateSK)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProof(proof); err != nil {
		t.Fatal(err)
	}
	if proof.Package["schema"] != ProofSchema {
		t.Fatalf("schema = %v", proof.Package["schema"])
	}
	if proof.Package["tenant_id_hash"] != tenantHash {
		t.Fatalf("tenant_id_hash = %v", proof.Package["tenant_id_hash"])
	}
}

func TestVerifyReceipt(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewTestReceipt(priv, "dest-1", "operator-a", "sha256:aa", "sha256:bb", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceipt(r); err != nil {
		t.Fatal(err)
	}
	r.Signature = "00"
	if err := VerifyReceipt(r); err == nil {
		t.Fatal("expected verify failure")
	}
}
