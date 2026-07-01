package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"strings"

	"nexqloud-sealed/internal/destruction"
	"nexqloud-sealed/internal/registry"
)

func main() {
	registryURL := flag.String("registry", "http://127.0.0.1:7001", "federated registry base URL")
	aggregatorURL := flag.String("aggregator", "http://127.0.0.1:7004", "destruction aggregator base URL")
	operators := flag.String("operators", "", "operator dispatch map: operator-a=http://host:port,operator-b=...")
	addr := flag.String("addr", ":7003", "listen address")
	jwksURL := flag.String("jwks", "", "customer IdP JWKS URL for delete authorization")
	coordinatorKeyHex := flag.String("coordinator-key-hex", "", "optional 64-byte Ed25519 coordinator seed hex")
	flag.Parse()

	reg := registry.NewHTTPClient(*registryURL)
	coord := destruction.NewCoordinator(reg, *aggregatorURL, destruction.ParseOperatorURLs(*operators))
	if *jwksURL != "" {
		sk, err := destruction.LoadCoordinatorKey(*coordinatorKeyHex)
		if err != nil {
			log.Fatalf("coordinator key: %v", err)
		}
		coord.SetAuth(*jwksURL, sk)
		if *coordinatorKeyHex == "" {
			log.Printf("coordinator pubkey (pass to operators): %x", destruction.CoordinatorPublicKey(sk))
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/destructions", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			handleCreateDestruction(w, r, coord)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/destructions/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/destructions/")
		if id == "" {
			http.Error(w, "destruction id required", http.StatusBadRequest)
			return
		}
		session, ok := coord.GetSession(id)
		if !ok {
			http.Error(w, "destruction not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, session)
	})

	log.Printf("destruction coordinator listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func handleCreateDestruction(w http.ResponseWriter, r *http.Request, coord *destruction.Coordinator) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var req destruction.CreateDestructionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	session, err := coord.CreateDestruction(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, session)
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
