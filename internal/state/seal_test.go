package state

import (
	"bytes"
	"testing"
)

func TestSealAndOpen(t *testing.T) {
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	plaintext := []byte("dummy sealed state payload")

	blob := Seal(dek, plaintext)

	opened, err := Open(dek, blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("plaintext mismatch:\n  got  %q\n  want %q", opened, plaintext)
	}

	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := Open(dek, tampered); err == nil {
		t.Fatal("expected error after flipping ciphertext byte")
	}
}
