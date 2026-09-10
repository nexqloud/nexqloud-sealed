package chat

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"nexqloud-sealed/internal/identity"
	"nexqloud-sealed/internal/inference"
	"nexqloud-sealed/internal/receipt"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	return &Engine{
		Inference: inference.NewMock(),
		Seal: func(in receipt.Input) (*receipt.SealedReceipt, error) {
			return &receipt.SealedReceipt{
				Package: receipt.Package{
					Schema:    receipt.InferenceSchema,
					ReceiptID: "rcpt-" + uuid.NewString(),
				},
			}, nil
		},
		Materials: Materials{
			Seed:       bytes.Repeat([]byte{0x01}, 32),
			Chip:       bytes.Repeat([]byte{0x02}, 32),
			AttestBind: bytes.Repeat([]byte{0x03}, 32),
			KeyVersion: 1,
		},
	}
}

func testIdentity() identity.VerifiedIdentity {
	id := identity.DevIdentity("acme")
	id.Hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return id
}

func TestTurnRoundTrip(t *testing.T) {
	eng := testEngine(t)
	id := testIdentity()

	first, err := eng.Turn(id, inference.Request{Model: "m", Prompt: "hello"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.EncryptedPayload == "" || first.ReceiptID == "" {
		t.Fatalf("missing payload/receipt: %+v", first)
	}

	second, err := eng.Turn(id, inference.Request{
		Model:            "m",
		Prompt:           "again",
		EncryptedPayload: first.EncryptedPayload,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	msgs, err := eng.Decrypt(id, second.EncryptedPayload)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 4 {
		t.Fatalf("want 4 messages, got %d: %+v", len(msgs), msgs)
	}
	if msgs[0].Content != "hello" || msgs[2].Content != "again" {
		t.Fatalf("history mismatch: %+v", msgs)
	}
	if msgs[1].ReceiptID == "" || msgs[3].ReceiptID == "" {
		t.Fatalf("missing receipt ids: %+v", msgs)
	}
}

func TestTurnRejectsTamperedPayload(t *testing.T) {
	eng := testEngine(t)
	id := testIdentity()
	first, err := eng.Turn(id, inference.Request{Prompt: "hello"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(first.EncryptedPayload)
	raw[len(raw)-1] ^= 0xff
	_, err = eng.Turn(id, inference.Request{
		Prompt:           "again",
		EncryptedPayload: string(raw),
	}, nil)
	if !IsInvalidPayload(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestDecryptEmpty(t *testing.T) {
	eng := testEngine(t)
	msgs, err := eng.Decrypt(testIdentity(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatalf("got %v", msgs)
	}
}

func TestTurnUsesLastUserMessageFallback(t *testing.T) {
	eng := testEngine(t)
	out, err := eng.Turn(testIdentity(), inference.Request{
		Messages: []inference.Message{{Role: "user", Content: "from messages"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := eng.Decrypt(testIdentity(), out.EncryptedPayload)
	if err != nil {
		t.Fatal(err)
	}
	if msgs[0].Content != "from messages" {
		t.Fatalf("got %q", msgs[0].Content)
	}
}

func TestTurnStreamsTokens(t *testing.T) {
	eng := testEngine(t)
	var got strings.Builder
	out, err := eng.Turn(testIdentity(), inference.Request{Prompt: "hi"}, func(tok string) error {
		got.WriteString(tok)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != out.Content {
		t.Fatalf("streamed %q vs %q", got.String(), out.Content)
	}
}

func TestTurnReceiptFailureStillEncrypts(t *testing.T) {
	eng := testEngine(t)
	eng.Seal = func(in receipt.Input) (*receipt.SealedReceipt, error) {
		return nil, fmt.Errorf("wipe worker down")
	}
	out, err := eng.Turn(testIdentity(), inference.Request{Prompt: "hello"}, nil)
	if err == nil {
		t.Fatal("expected receipt error")
	}
	if !strings.Contains(err.Error(), "receipt:") {
		t.Fatalf("err = %v", err)
	}
	if out.Content == "" || out.EncryptedPayload == "" {
		t.Fatalf("expected content and ciphertext after receipt failure: %+v", out)
	}
	msgs, err := eng.Decrypt(testIdentity(), out.EncryptedPayload)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[0].Content != "hello" || msgs[1].ReceiptID != "" {
		t.Fatalf("got %+v", msgs)
	}
}

func TestOpenDoesNotUseClientHistory(t *testing.T) {
	eng := testEngine(t)
	id := testIdentity()
	first, err := eng.Turn(id, inference.Request{Prompt: "real"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := eng.Turn(id, inference.Request{
		Prompt:           "next",
		EncryptedPayload: first.EncryptedPayload,
		Messages: []inference.Message{
			{Role: "user", Content: "injected"},
			{Role: "assistant", Content: "fake"},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := eng.Decrypt(id, second.EncryptedPayload)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.Content == "injected" || m.Content == "fake" {
			t.Fatalf("client history leaked into TEE state: %+v", msgs)
		}
	}
	if len(msgs) != 4 {
		t.Fatalf("want 4, got %+v", msgs)
	}
}
