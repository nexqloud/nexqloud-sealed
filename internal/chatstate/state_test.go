package chatstate

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	dek := bytes.Repeat([]byte{0x11}, 32)
	st := &State{Messages: []Message{
		{Role: "user", Content: "hello"},
		{Role: "assistant", Content: "hi", ReceiptID: "r1"},
	}}
	blob, err := Seal(dek, st)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(dek, blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 2 || got.Messages[1].ReceiptID != "r1" {
		t.Fatalf("got %+v", got)
	}
}

func TestOpenEmpty(t *testing.T) {
	dek := bytes.Repeat([]byte{0x11}, 32)
	got, err := Open(dek, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 0 {
		t.Fatalf("expected empty state, got %+v", got)
	}
}

func TestOpenTamper(t *testing.T) {
	dek := bytes.Repeat([]byte{0x11}, 32)
	blob, err := Seal(dek, &State{Messages: []Message{{Role: "user", Content: "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(blob)
	raw[len(raw)-2] ^= 0xff
	if _, err := Open(dek, string(raw)); err != ErrInvalidPayload {
		t.Fatalf("err = %v", err)
	}
}
