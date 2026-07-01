package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"strings"

	"nexqloud-sealed/internal/destruction"
)

func main() {
	addr := flag.String("addr", ":7004", "listen address")
	substrateKeyHex := flag.String("substrate-key-hex", "", "optional 32-byte Ed25519 seed hex for aggregator signing key")
	flag.Parse()

	sk, err := destruction.LoadSubstrateKey(*substrateKeyHex)
	if err != nil {
		log.Fatalf("substrate key: %v", err)
	}
	pub := sk.Public()
	log.Printf("aggregator substrate pubkey: %s", hex.EncodeToString(pub.(ed25519.PublicKey)))

	agg := destruction.NewAggregator(sk)

	mux := http.NewServeMux()
	mux.HandleFunc("/destructions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleRegister(w, r, agg)
	})
	mux.HandleFunc("/destructions/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/destructions/")
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			http.Error(w, "destruction id required", http.StatusBadRequest)
			return
		}
		id := parts[0]

		if len(parts) == 2 && parts[1] == "receipts" {
			switch r.Method {
			case http.MethodPost:
				handleSubmitReceipt(w, r, agg, id)
			case http.MethodGet:
				handleGetReceipts(w, r, agg, id)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}
		if len(parts) == 2 && parts[1] == "aggregate" {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			handleAggregate(w, r, agg, id)
			return
		}
		if len(parts) == 2 && parts[1] == "proof" {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			handleGetProof(w, r, agg, id)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	})

	log.Printf("destruction aggregator listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func handleRegister(w http.ResponseWriter, r *http.Request, agg *destruction.Aggregator) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var req destruction.RegisterRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if err := agg.Register(req); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"destruction_id": req.DestructionID,
		"status":         "registered",
	})
}

func handleSubmitReceipt(w http.ResponseWriter, r *http.Request, agg *destruction.Aggregator, destructionID string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var receipt destruction.Receipt
	if err := json.Unmarshal(body, &receipt); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	proof, complete, err := agg.SubmitReceipt(destructionID, receipt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if complete {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "aggregated",
			"proof":  proof,
		})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{
		"status": "receipt stored",
	})
}

func handleAggregate(w http.ResponseWriter, r *http.Request, agg *destruction.Aggregator, destructionID string) {
	proof, err := agg.Aggregate(destructionID)
	if err != nil {
		if strings.Contains(err.Error(), "incomplete quorum") {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, proof)
}

func handleGetReceipts(w http.ResponseWriter, r *http.Request, agg *destruction.Aggregator, destructionID string) {
	pending, ok := agg.GetPending(destructionID)
	if !ok {
		http.Error(w, "destruction not found", http.StatusNotFound)
		return
	}
	receipts := make([]destruction.Receipt, 0, len(pending.Receipts))
	for _, rcpt := range pending.Receipts {
		receipts = append(receipts, rcpt)
	}
	if len(receipts) == 0 {
		http.Error(w, "no receipts yet", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"destruction_id": destructionID,
		"receipts":       receipts,
	})
}

func handleGetProof(w http.ResponseWriter, r *http.Request, agg *destruction.Aggregator, destructionID string) {
	proof, ok := agg.GetProof(destructionID)
	if !ok {
		http.Error(w, "proof not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, proof)
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
