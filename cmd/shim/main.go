package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"

	"nexqloud-sealed/internal/enclave"
	"nexqloud-sealed/internal/inference"
	"nexqloud-sealed/internal/receipt"
)

type server struct {
	inference inference.Backend
	receipt   *receipt.Builder
}

func main() {
	// 1. This keypair is the shim's receipt signing identity. Every sealed_receipt is signed with priv, and verifiers see pub in the receipt.
	priv, pub, err := enclave.Key()
	if err != nil {
		log.Fatalf("generate enclave key: %v", err)
	}

	log.Printf("warming AMD KDS certificate cache (VCEK, ASK, ARK)...")
	if err := enclave.WarmCertificateCache(pub); err != nil {
		log.Fatalf("warm certificate cache: %v", err)
	}
	log.Printf("AMD certificate cache ready")

	srv := &server{
		inference: selectInferenceBackend(),
		receipt:   receipt.NewBuilder(priv, pub),
	}

	http.HandleFunc("/v1/chat/completions", srv.handleChatCompletions)

	addr := ":8080"
	log.Printf("sealed-shim listening on %s (inference=%T)", addr, srv.inference)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func selectInferenceBackend() inference.Backend {
	if url := os.Getenv("VLLM_URL"); url != "" {
		log.Printf("inference backend: vLLM at %s", url)
		return inference.NewVLLM(url)
	}
	log.Printf("inference backend: mock (set VLLM_URL to use real vLLM)")
	return inference.NewMock()
}

func (s *server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var req inference.Request
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// ── Inference boundary: sealed-shim does NOT run the model here ──
	inferOut, err := s.inference.Complete(req)
	if err != nil {
		http.Error(w, "inference failed", http.StatusBadGateway)
		return
	}

	// ── Trust boundary: sealed-shim wraps the result in a verifiable receipt ──
	sealedReceipt, err := s.receipt.Seal(receipt.Input{
		Prompt:   extractPrompt(req),
		Response: inferOut.Content,
	})
	if err != nil {
		log.Printf("receipt build failed: %v", err)
		http.Error(w, "receipt build failed", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"id":      "chatcmpl-" + uuid.NewString(),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   inferOut.Model,
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": inferOut.Content,
				},
				"finish_reason": "stop",
			},
		},
		"sealed_receipt": sealedReceipt,
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(resp); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func extractPrompt(req inference.Request) string {
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			return req.Messages[i].Content
		}
	}
	if len(req.Messages) > 0 {
		return req.Messages[len(req.Messages)-1].Content
	}
	return ""
}
