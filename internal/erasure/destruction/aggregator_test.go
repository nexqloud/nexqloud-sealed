package destruction

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAggregatorFlow(t *testing.T) {
	_, substrateSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, opAPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, opBPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	agg := NewAggregator(substrateSK)
	err = agg.Register(RegisterRequest{
		DestructionID: "dest-1",
		TenantID:      "acme",
		Quorum:        []string{"operator-a", "operator-b"},
		SeedCommit:    "sha256:abc",
		KeyVersion:    1,
	})
	if err != nil {
		t.Fatal(err)
	}

	tenantHash := "sha256:822b33ad87c148a0a20a5ba7cd5ebcaa68d36a18e7aad165554903f52ca82757"
	rA, err := NewTestReceipt(opAPriv, "dest-1", "operator-a", tenantHash, "sha256:abc", 1)
	if err != nil {
		t.Fatal(err)
	}
	proof, complete, err := agg.SubmitReceipt("dest-1", rA)
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Fatal("should not complete with one receipt")
	}

	rB, err := NewTestReceipt(opBPriv, "dest-1", "operator-b", tenantHash, "sha256:abc", 1)
	if err != nil {
		t.Fatal(err)
	}
	proof, complete, err = agg.SubmitReceipt("dest-1", rB)
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("expected auto-aggregate")
	}
	if err := VerifyProof(proof); err != nil {
		t.Fatal(err)
	}

	got, ok := agg.GetProof("dest-1")
	if !ok {
		t.Fatal("proof not stored")
	}
	if got.Signature != proof.Signature {
		t.Fatal("proof mismatch")
	}
}

func TestAggregatorIncompleteAggregate(t *testing.T) {
	_, substrateSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agg := NewAggregator(substrateSK)
	agg.Register(RegisterRequest{
		DestructionID: "dest-2",
		TenantID:      "acme",
		Quorum:        []string{"operator-a", "operator-b"},
		SeedCommit:    "sha256:abc",
		KeyVersion:    1,
	})

	_, err = agg.Aggregate("dest-2")
	if err == nil || err.Error() != "incomplete quorum: data would remain recoverable" {
		t.Fatalf("err = %v", err)
	}
}

func TestAggregatorHTTP(t *testing.T) {
	_, substrateSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, opAPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, opBPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	agg := NewAggregator(substrateSK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/destructions":
			body, _ := io.ReadAll(r.Body)
			var req RegisterRequest
			json.Unmarshal(body, &req)
			if err := agg.Register(req); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
		case r.Method == http.MethodPost && r.URL.Path == "/destructions/dest-http/receipts":
			body, _ := io.ReadAll(r.Body)
			var receipt Receipt
			json.Unmarshal(body, &receipt)
			proof, complete, err := agg.SubmitReceipt("dest-http", receipt)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if complete {
				json.NewEncoder(w).Encode(map[string]any{"status": "aggregated", "proof": proof})
				return
			}
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPost && r.URL.Path == "/destructions/dest-http/aggregate":
			proof, err := agg.Aggregate("dest-http")
			if err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			json.NewEncoder(w).Encode(proof)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	regBody, _ := json.Marshal(RegisterRequest{
		DestructionID: "dest-http",
		TenantID:      "acme",
		Quorum:        []string{"operator-a", "operator-b"},
		SeedCommit:    "sha256:abc",
		KeyVersion:    1,
	})
	resp, err := http.Post(srv.URL+"/destructions", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status %d", resp.StatusCode)
	}

	tenantHash := "sha256:aa"
	for _, pair := range []struct {
		priv ed25519.PrivateKey
		op   string
	}{
		{opAPriv, "operator-a"},
		{opBPriv, "operator-b"},
	} {
		r, err := NewTestReceipt(pair.priv, "dest-http", pair.op, tenantHash, "sha256:abc", 1)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(r)
		resp, err := http.Post(srv.URL+"/destructions/dest-http/receipts", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	proof, ok := agg.GetProof("dest-http")
	if !ok {
		t.Fatal("expected proof")
	}
	if err := VerifyProof(proof); err != nil {
		t.Fatal(err)
	}
}
