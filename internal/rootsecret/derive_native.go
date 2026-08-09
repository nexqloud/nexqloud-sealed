//go:build !(js && wasm)

package rootsecret

import (
	"fmt"

	"github.com/google/go-sev-guest/client"

	"nexqloud-sealed/internal/enclave"
)

const chipSecretSize = 32

func Chip() ([]byte, error) {
	device, err := client.OpenDevice()
	if err != nil {
		return nil, err
	}
	defer device.Close()

	resp, err := client.GetDerivedKeyAcknowledgingItsLimitations(device, enclave.DerivedKeyRequest())
	if err != nil {
		return nil, fmt.Errorf("SNP_GET_DERIVED_KEY: %w", err)
	}

	key := append([]byte(nil), resp.Data[:]...)
	if len(key) != chipSecretSize {
		return nil, fmt.Errorf("derived key length %d, want %d", len(key), chipSecretSize)
	}
	return key, nil
}
