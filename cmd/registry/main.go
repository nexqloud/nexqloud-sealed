// Command registry serves the federated key-derivation registry: the authoritative
// record of which operator nodes hold key-derivation material for each tenant.
//
// It is the persistence the destruction protocol depends on. The coordinator reads
// it to resolve the destruction quorum, each operator reads its own wrap from it to
// derive (and to seal a conversation's key scope), and the verifier reads it to
// confirm "destruction quorum matches registry wraps". Destroying a scope zeroes the
// wrap but keeps the operator's slot, so the quorum stays auditable afterwards.
//
// Routes (same shape as the demo registry, so this is a drop-in replacement):
//
//	POST   /records                              full record (onboarding)
//	GET    /records/<tenant>                     the tenant's record
//	PUT    /records/<tenant>/wraps/<operator>    register/re-seal one operator's wrap
//	DELETE /records/<tenant>/wraps/<operator>    destroy (zero) one operator's wrap
//	PUT    /records/<tenant>/callbacks/<operator> record the URL a coordinator can reach that operator on
//	GET    /healthz                              readiness
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"nexqloud-sealed/internal/registry"
	registrymongo "nexqloud-sealed/internal/registry/mongo"
)

type server struct {
	store *registrymongo.Store
}

func main() {
	addr := flag.String("addr", ":7001", "listen address")
	mongoURI := flag.String("mongo", os.Getenv("MONGO_URL"), "MongoDB connection string (or MONGO_URL)")
	db := flag.String("db", "sealed_registry", "MongoDB database")
	collection := flag.String("collection", "commitments", "MongoDB collection")
	flag.Parse()

	if strings.TrimSpace(*mongoURI) == "" {
		log.Fatal("mongo connection string is required (-mongo or MONGO_URL)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store, err := registrymongo.New(ctx, *mongoURI, *db, *collection)
	if err != nil {
		log.Fatalf("registry store: %v", err)
	}
	defer func() {
		shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = store.Close(shutdownCtx)
	}()

	srv := &server{store: store}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	// The registry can be published behind the public edge (operator nodes have to
	// reach it), so it can require a shared secret. Reads are gated too: the wraps it
	// holds are the erasure's only copy of the key material. /healthz stays open for
	// probes. (A constant-time compare is the next hardening step here.)
	registryToken := strings.TrimSpace(os.Getenv("SEALED_REGISTRY_TOKEN"))
	requireToken := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if registryToken == "" {
				next(w, r)
				return
			}
			if r.Header.Get("X-Sealed-Registry-Token") != registryToken {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}

	mux.HandleFunc("/records", requireToken(srv.handleRecords))
	mux.HandleFunc("/records/", requireToken(srv.handleRecordByTenant))

	httpServer := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Printf("registry shutting down")
		shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	log.Printf("federated registry listening on %s (db=%s collection=%s)", *addr, *db, *collection)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func (s *server) handleRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var record registry.CommitmentRecord
	if err := json.Unmarshal(body, &record); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(record.TenantID) == "" {
		http.Error(w, "tenant_id is required", http.StatusBadRequest)
		return
	}

	if err := s.store.Save(record); err != nil {
		if errors.Is(err, registrymongo.ErrSeedCommitConflict) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, record)
}

func (s *server) handleRecordByTenant(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/records/")
	if tenantID, operatorID, ok := splitWrapPath(path); ok {
		s.handleWrap(w, r, tenantID, operatorID)
		return
	}

	if tenantID, operatorID, ok := splitCallbacksPath(path); ok {
		s.handleCallback(w, r, tenantID, operatorID)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if path == "" {
		http.Error(w, "tenant_id is required", http.StatusBadRequest)
		return
	}

	record, found, err := s.store.Get(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "record not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (s *server) handleWrap(w http.ResponseWriter, r *http.Request, tenantID, operatorID string) {
	switch r.Method {
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var req struct {
			OperatorID string `json:"operator_id"`
			SeedCommit string `json:"seed_commit"`
			Wrap       string `json:"wrap"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if req.OperatorID != "" && req.OperatorID != operatorID {
			http.Error(w, "operator_id in body does not match path", http.StatusBadRequest)
			return
		}
		wrap, err := base64.StdEncoding.DecodeString(req.Wrap)
		if err != nil || len(wrap) == 0 {
			http.Error(w, "wrap must be base64", http.StatusBadRequest)
			return
		}
		if err := s.store.PutWrap(tenantID, operatorID, wrap, req.SeedCommit); err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, registrymongo.ErrSeedCommitConflict) {
				status = http.StatusConflict
			}
			http.Error(w, err.Error(), status)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":   tenantID,
			"operator_id": operatorID,
			"stored":      true,
		})

	case http.MethodDelete:
		destroyed, err := s.store.DestroyWrap(tenantID, operatorID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":   tenantID,
			"operator_id": operatorID,
			"destroyed":   destroyed,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// splitCallbacksPath recognises /records/<tenant>/callbacks/<operator>.
func splitCallbacksPath(path string) (tenantID, operatorID string, ok bool) {
	tenantID, rest, found := strings.Cut(path, "/callbacks/")
	if !found || tenantID == "" || rest == "" {
		return "", "", false
	}
	return tenantID, rest, true
}

// handleCallback records the URL a coordinator can reach one operator node on, so a
// deployment self-registers instead of being hand-added to a coordinator's operator
// map.
func (s *server) handleCallback(w http.ResponseWriter, r *http.Request, tenantID, operatorID string) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req struct {
		CallbackURL string `json:"callback_url"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if err := s.store.PutCallback(tenantID, operatorID, req.CallbackURL); err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "record not found") {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id":    tenantID,
		"operator_id":  operatorID,
		"callback_url": req.CallbackURL,
	})
}

func splitWrapPath(path string) (tenantID, operatorID string, ok bool) {
	tenantID, rest, found := strings.Cut(path, "/wraps/")
	if !found || tenantID == "" || rest == "" {
		return "", "", false
	}
	return tenantID, rest, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		log.Printf("encode response: %v", err)
	}
}
