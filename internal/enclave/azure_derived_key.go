package enclave

import (
	"encoding/binary"
	"fmt"
)

const measurementGuestFieldSelect = 0b100000

func AzureRequestDerivedKey() ([]byte, error) {
	tpm, err := openAzureTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	if err := writeNVIndex(tpm, azureDerivedKeyRequestNVIndex, derivedKeyRequestBlob()); err != nil {
		return nil, err
	}

	resp, err := readNVIndex(tpm, azureDerivedKeyResponseNVIndex)
	if err != nil {
		return nil, fmt.Errorf("read derived key from vTPM: %w", err)
	}
	if len(resp) < azureDerivedKeyResponseSize {
		return nil, fmt.Errorf("derived key response too short: got %d bytes, need %d", len(resp), azureDerivedKeyResponseSize)
	}

	status := binary.LittleEndian.Uint32(resp[:4])
	if status != 0 {
		return nil, fmt.Errorf("derived key request failed with status 0x%x", status)
	}

	return append([]byte(nil), resp[azureDerivedKeyResponseDataOff:azureDerivedKeyResponseDataOff+32]...), nil
}

func derivedKeyRequestBlob() []byte {
	buf := make([]byte, 32)
	binary.LittleEndian.PutUint32(buf[0:4], 0)
	binary.LittleEndian.PutUint64(buf[8:16], measurementGuestFieldSelect)
	return buf
}
