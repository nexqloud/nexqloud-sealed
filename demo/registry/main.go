package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"nexqloud-sealed/demo/registry/memstore"
	"nexqloud-sealed/internal/registry"
)

type server struct {
	store *memstore.Store
}

func main() {
	srv := &server{store: memstore.New()}

	http.HandleFunc("/records", srv.handleRecords)
	http.HandleFunc("/records/", srv.handleRecordByTenant)

	addr := ":7001"
	log.Printf("demo federated registry listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
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
	if record.TenantID == "" {
		http.Error(w, "tenant_id is required", http.StatusBadRequest)
		return
	}

	if err := s.store.Save(record); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(record); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func (s *server) handleRecordByTenant(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/records/")
	if tenantID, operatorID, ok := splitWrapPath(path); ok {
		s.handleWrap(w, r, tenantID, operatorID)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantID := path
	if tenantID == "" {
		http.Error(w, "tenant_id is required", http.StatusBadRequest)
		return
	}

	record, ok := s.store.Get(tenantID)
	if !ok {
		http.Error(w, "record not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(record); err != nil {
		log.Printf("encode response: %v", err)
	}
}

// splitWrapPath recognises <tenant>/wraps/<operator>.
func splitWrapPath(path string) (tenantID, operatorID string, ok bool) {
	tenantID, rest, found := strings.Cut(path, "/wraps/")
	if !found || tenantID == "" || rest == "" {
		return "", "", false
	}
	return tenantID, rest, true
}

// handleWrap is the mutation surface of the registry: PUT registers an
// operator's sealed key material, DELETE clears it so a destruction is durable.
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
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":   tenantID,
			"operator_id": operatorID,
			"stored":      true,
		})

	case http.MethodDelete:
		destroyed := s.store.DestroyWrap(tenantID, operatorID)
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":   tenantID,
			"operator_id": operatorID,
			"destroyed":   destroyed,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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
