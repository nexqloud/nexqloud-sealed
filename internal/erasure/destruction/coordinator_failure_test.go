package destruction

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nexqloud-sealed/internal/federation"
	"nexqloud-sealed/internal/registry"
)

func TestCoordinatorUnreachableOperatorExclusion(t *testing.T) {
	t.Cleanup(federation.Reset)

	regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := registry.CommitmentRecord{
			TenantID:   "acme",
			KeyVersion: 1,
			SeedCommit: "sha256:abc",
			Wraps: map[string][]byte{
				"operator-a": {1},
				"operator-b": {2},
			},
		}
		json.NewEncoder(w).Encode(rec)
	}))
	defer regSrv.Close()

	aggSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/destructions" {
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/exclusions") {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer aggSrv.Close()

	opASrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer opASrv.Close()

	reg := registry.NewHTTPClient(regSrv.URL)
	coord := NewCoordinator(reg, aggSrv.URL, map[string]string{
		"operator-a": opASrv.URL,
		"operator-b": "http://127.0.0.1:1",
	})
	coord.HTTPClient = &http.Client{Timeout: 50 * time.Millisecond}

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	coord.SetAuth("", sk)
	coord.FailureHandler = NewFailureHandler(sk, nil)
	coord.FailureHandler.BaseDelay = time.Millisecond
	coord.FailureHandler.MaxRetries = 2

	session, err := coord.CreateDestruction(t.Context(), CreateDestructionRequest{TenantID: "acme"})
	if err != nil {
		t.Fatal(err)
	}

	var excluded bool
	var dispatched bool
	for _, d := range session.Dispatches {
		switch d.OperatorID {
		case "operator-b":
			if d.Status == "erased_by_exclusion" {
				excluded = true
			}
		case "operator-a":
			if d.Status == "dispatched" {
				dispatched = true
			}
		}
	}
	if !dispatched {
		t.Fatalf("operator-a not dispatched: %+v", session.Dispatches)
	}
	if !excluded {
		t.Fatalf("operator-b not excluded: %+v", session.Dispatches)
	}
	if !federation.IsExcluded("operator-b", "acme") {
		t.Fatal("operator-b not in federation exclusion set")
	}
	if len(session.Quorum) != 1 || session.Quorum[0] != "operator-a" {
		t.Fatalf("quorum = %v", session.Quorum)
	}
}

func TestAggregatorExcludeOperator(t *testing.T) {
	_, substrateSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agg := NewAggregator(substrateSK)
	if err := agg.Register(RegisterRequest{
		DestructionID: "dest-ex",
		TenantID:      "acme",
		Quorum:        []string{"operator-a", "operator-b"},
		SeedCommit:    "sha256:abc",
		KeyVersion:    1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := agg.ExcludeOperator("dest-ex", "operator-b"); err != nil {
		t.Fatal(err)
	}
	pending, ok := agg.GetPending("dest-ex")
	if !ok {
		t.Fatal("pending not found")
	}
	if len(pending.Quorum) != 1 || pending.Quorum[0] != "operator-a" {
		t.Fatalf("quorum = %v", pending.Quorum)
	}
	if len(pending.Exclusions) != 1 || pending.Exclusions[0] != "operator-b" {
		t.Fatalf("exclusions = %v", pending.Exclusions)
	}
}
