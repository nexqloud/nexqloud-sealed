package enclave

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const (
	azureHCLReportNVIndex  = 0x01400001
	azureReportDataNVIndex = 0x01400002
	azureHCLReportOffset   = 32
)

func openAzureTPM() (transport.TPMCloser, error) {
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		tpm, err = linuxtpm.Open("/dev/tpm0")
		if err != nil {
			return nil, fmt.Errorf("open tpm device: %w", err)
		}
	}
	return tpm, nil
}

func writeNVIndex(t transport.TPM, index uint32, data []byte) error {
	_, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}.Execute(t)
	if err != nil {
		return fmt.Errorf("nv index 0x%x unavailable: %w", index, err)
	}

	nvName, err := nvIndexName(t, index)
	if err != nil {
		return fmt.Errorf("resolve nv index 0x%x: %w", index, err)
	}

	_, err = tpm2.NVWrite{
		AuthHandle: ownerAuthHandle(),
		NVIndex:    nvName,
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: data},
	}.Execute(t)
	if err != nil {
		return fmt.Errorf("write nv index 0x%x: %w", index, err)
	}
	return nil
}

func readNVIndex(t transport.TPM, index uint32) ([]byte, error) {
	readPub, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}.Execute(t)
	if err != nil {
		return nil, err
	}

	pub, err := readPub.NVPublic.Contents()
	if err != nil {
		return nil, err
	}

	nvName, err := nvIndexName(t, index)
	if err != nil {
		return nil, err
	}

	var out []byte
	remaining := pub.DataSize
	offset := uint16(0)
	for remaining > 0 {
		chunk := remaining
		if chunk > 1024 {
			chunk = 1024
		}

		read, err := tpm2.NVRead{
			AuthHandle: ownerAuthHandle(),
			NVIndex:    nvName,
			Offset:     offset,
			Size:       chunk,
		}.Execute(t)
		if err != nil {
			return nil, err
		}

		out = append(out, read.Data.Buffer...)
		offset += chunk
		remaining -= chunk
	}
	return out, nil
}

func nvIndexName(t transport.TPM, index uint32) (tpm2.NamedHandle, error) {
	readPub, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}.Execute(t)
	if err != nil {
		return tpm2.NamedHandle{}, err
	}
	return tpm2.NamedHandle{
		Handle: tpm2.TPMHandle(index),
		Name:   readPub.NVName,
	}, nil
}

func ownerAuthHandle() tpm2.AuthHandle {
	return tpm2.AuthHandle{
		Handle: tpm2.TPMRHOwner,
		Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte{})),
	}
}
