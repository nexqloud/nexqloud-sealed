package rootsecret

import (
	"errors"
	"fmt"

	"github.com/google/go-sev-guest/client"

	"nexqloud-sealed/internal/enclave"
)

const chipSecretSize = 32

func Chip() ([]byte, error) {
	key, nativeErr := nativeChip()
	if nativeErr == nil {
		return key, nil
	}

	key, azureErr := enclave.AzureRequestDerivedKey()
	if azureErr == nil {
		if len(key) != chipSecretSize {
			return nil, fmt.Errorf("derived key length %d, want %d", len(key), chipSecretSize)
		}
		return key, nil
	}

	return nil, errors.Join(
		fmt.Errorf("native /dev/sev-guest: %w", nativeErr),
		fmt.Errorf("azure vTPM: %w", azureErr),
	)
}

func nativeChip() ([]byte, error) {
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
