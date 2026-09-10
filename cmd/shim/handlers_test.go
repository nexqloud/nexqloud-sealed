package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"nexqloud-sealed/internal/chat"
	"nexqloud-sealed/internal/inference"
	"nexqloud-sealed/internal/receipt"
)

func testHTTPServer(t *testing.T) *server {
	t.Helper()
	t.Setenv("NEXQLOUD_DEV", "1")
	srv := &server{
		engine: &chat.Engine{
			Inference: inference.NewMock(),
			Seal: func(in receipt.Input) (*receipt.SealedReceipt, error) {
				return &receipt.SealedReceipt{
					Package: receipt.Package{
						Schema:    receipt.InferenceSchema,
						ReceiptID: "rcpt-" + uuid.NewString(),
					},
				}, nil
			},
			Materials: chat.Materials{
				Seed:       bytes.Repeat([]byte{0x01}, 32),
				Chip:       bytes.Repeat([]byte{0x02}, 32),
				AttestBind: bytes.Repeat([]byte{0x03}, 32),
				KeyVersion: 1,
			},
		},
	}
	srv.ready.Store(true)
	return srv
}

func TestHandleChatCompletionsRoundTrip(t *testing.T) {
	srv := testHTTPServer(t)
	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"prompt":"hello"}`))
	srv.handleChatCompletions(first, req)
	if first.Code != 200 {
		t.Fatalf("status %d body %s", first.Code, first.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(first.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	payload, _ := body["encrypted_payload"].(string)
	receiptID, _ := body["receipt_id"].(string)
	if payload == "" || receiptID == "" {
		t.Fatalf("missing fields: %v", body)
	}

	second := httptest.NewRecorder()
	raw, _ := json.Marshal(map[string]any{
		"prompt":            "again",
		"encrypted_payload": payload,
	})
	req2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(raw))
	srv.handleChatCompletions(second, req2)
	if second.Code != 200 {
		t.Fatalf("second status %d body %s", second.Code, second.Body.String())
	}

	dec := httptest.NewRecorder()
	raw, _ = json.Marshal(map[string]any{"encrypted_payload": json.RawMessage(second.Body.Bytes())})
	var secondBody map[string]any
	_ = json.Unmarshal(second.Body.Bytes(), &secondBody)
	payload2, _ := secondBody["encrypted_payload"].(string)
	raw, _ = json.Marshal(map[string]any{"encrypted_payload": payload2})
	req3 := httptest.NewRequest(http.MethodPost, "/v1/chat/decrypt", bytes.NewReader(raw))
	srv.handleDecrypt(dec, req3)
	if dec.Code != 200 {
		t.Fatalf("decrypt status %d body %s", dec.Code, dec.Body.String())
	}
	var hist struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(dec.Body.Bytes(), &hist); err != nil {
		t.Fatal(err)
	}
	if len(hist.Messages) != 4 {
		t.Fatalf("got %+v", hist)
	}
}

func TestHandleChatCompletionsRejectsTamper(t *testing.T) {
	srv := testHTTPServer(t)
	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"prompt":"hello"}`))
	srv.handleChatCompletions(first, req)
	var body map[string]any
	_ = json.Unmarshal(first.Body.Bytes(), &body)
	payload, _ := body["encrypted_payload"].(string)
	raw := []byte(payload)
	raw[len(raw)-1] ^= 0xff
	second := httptest.NewRecorder()
	b, _ := json.Marshal(map[string]any{"prompt": "again", "encrypted_payload": string(raw)})
	req2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(b))
	srv.handleChatCompletions(second, req2)
	if second.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", second.Code, second.Body.String())
	}
}

func TestHandleChatCompletionsStream(t *testing.T) {
	srv := testHTTPServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"prompt":"hello","stream":true}`))
	srv.handleChatCompletions(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if !strings.Contains(out, "event: token") || !strings.Contains(out, "event: sealed") {
		t.Fatalf("sse missing events: %s", out)
	}
}

func TestHandleChatCompletionsReceiptErrorKeepsPayload(t *testing.T) {
	srv := testHTTPServer(t)
	srv.engine.Seal = func(in receipt.Input) (*receipt.SealedReceipt, error) {
		return nil, fmt.Errorf("wipe worker down")
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"prompt":"hello"}`))
	srv.handleChatCompletions(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["encrypted_payload"] == "" || body["receipt_error"] == nil {
		t.Fatalf("missing payload or receipt_error: %v", body)
	}
}

func TestHandleDecryptEmpty(t *testing.T) {
	srv := testHTTPServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/decrypt", strings.NewReader(`{}`))
	srv.handleDecrypt(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	raw, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(raw), `"messages"`) {
		t.Fatalf("body %s", raw)
	}
}
