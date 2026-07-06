package destruction

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nexqloud-sealed/internal/registry"
)

func TestCoordinatorCreateDestruction(t *testing.T) {
	regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/records/acme" {
			http.NotFound(w, r)
			return
		}
		rec := registry.CommitmentRecord{
			TenantID:   "acme",
			KeyVersion: 1,
			SeedCommit: "sha256:abc",
			Wraps: map[string][]byte{
				"operator-a": {1},
				"operator-b": {2},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rec)
	}))
	defer regSrv.Close()

	var registered bool
	aggSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/destructions" {
			registered = true
			w.WriteHeader(http.StatusCreated)
			return
		}
		http.NotFound(w, r)
	}))
	defer aggSrv.Close()

	reg := registry.NewHTTPClient(regSrv.URL)
	coord := NewCoordinator(reg, aggSrv.URL, nil)

	session, err := coord.CreateDestruction(t.Context(), CreateDestructionRequest{TenantID: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if !registered {
		t.Fatal("aggregator not registered")
	}
	if len(session.Quorum) != 2 {
		t.Fatalf("quorum = %v", session.Quorum)
	}
	if session.TenantID != "acme" {
		t.Fatalf("tenant_id = %q", session.TenantID)
	}
	if session.Status != "partial" {
		t.Fatalf("status = %q", session.Status)
	}
	for _, d := range session.Dispatches {
		if d.Status != "skipped" {
			t.Fatalf("dispatch = %+v", d)
		}
	}

	got, ok := coord.GetSession(session.DestructionID)
	if !ok {
		t.Fatal("session not stored")
	}
	if got.DestructionID != session.DestructionID {
		t.Fatalf("stored id = %q", got.DestructionID)
	}
}

func TestParseOperatorURLs(t *testing.T) {
	m := ParseOperatorURLs("operator-a=http://a:8080, operator-b=http://b:9090")
	if m["operator-a"] != "http://a:8080" {
		t.Fatalf("a = %q", m["operator-a"])
	}
	if m["operator-b"] != "http://b:9090" {
		t.Fatalf("b = %q", m["operator-b"])
	}
}

func TestCoordinatorHTTP(t *testing.T) {
	regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := registry.CommitmentRecord{
			TenantID:   "acme",
			KeyVersion: 1,
			SeedCommit: "sha256:abc",
			Wraps:      map[string][]byte{"operator-a": {1}},
		}
		json.NewEncoder(w).Encode(rec)
	}))
	defer regSrv.Close()

	aggSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer aggSrv.Close()

	reg := registry.NewHTTPClient(regSrv.URL)
	coord := NewCoordinator(reg, aggSrv.URL, nil)

	coordSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/destructions" {
			body, _ := io.ReadAll(r.Body)
			var req CreateDestructionRequest
			json.Unmarshal(body, &req)
			session, err := coord.CreateDestruction(r.Context(), CreateDestructionRequest{TenantID: req.TenantID})
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(session)
			return
		}
		http.NotFound(w, r)
	}))
	defer coordSrv.Close()

	resp, err := http.Post(coordSrv.URL+"/destructions", "application/json", strings.NewReader(`{"tenant_id":"acme"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
}
