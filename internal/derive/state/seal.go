package state

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

func Seal(dek, plaintext []byte) []byte {
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		panic(fmt.Sprintf("chacha20poly1305.NewX: %v", err))
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(fmt.Sprintf("generate nonce: %v", err))
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...)
}

func Open(dek, blob []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(blob) < nonceSize {
		return nil, errors.New("blob too short")
	}

	nonce := blob[:nonceSize]
	ciphertext := blob[nonceSize:]
	return aead.Open(nil, nonce, ciphertext, nil)
}
