package kdf

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const dekLength = 32

func DeriveDEK(seed, chipSecret, claimHash, attestBind []byte, tenantID string, version int) ([]byte, error) {
	ikm := append(seed, chipSecret...)
	salt := append(claimHash, attestBind...)
	info := []byte(fmt.Sprintf("sealed-dek/1|%s|v%d", tenantID, version))

	r := hkdf.New(sha256.New, ikm, salt, info)
	dek := make([]byte, dekLength)
	if _, err := io.ReadFull(r, dek); err != nil {
		return nil, err
	}
	return dek, nil
}
