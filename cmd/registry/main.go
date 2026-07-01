package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"nexqloud-sealed/internal/registry"
)

type server struct {
	store *registry.Store
}

func main() {
	srv := &server{store: registry.NewStore()}

	http.HandleFunc("/records", srv.handleRecords)
	http.HandleFunc("/records/", srv.handleRecordByTenant)

	addr := ":7001"
	log.Printf("federated registry listening on %s", addr)
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

	s.store.Save(record)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(record); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func (s *server) handleRecordByTenant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantID := strings.TrimPrefix(r.URL.Path, "/records/")
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
