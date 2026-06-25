package enclave

import (
	"fmt"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const (
	azureHCLReportNVIndex  = 0x01400001
	azureReportDataNVIndex = 0x01400002
	azureHCLReportOffset   = 32
)

func azureRequestReport(reportData [64]byte) (*sevsnp.Attestation, error) {
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		tpm, err = linuxtpm.Open("/dev/tpm0")
		if err != nil {
			return nil, fmt.Errorf("open tpm device: %w", err)
		}
	}
	defer tpm.Close()

	if err := azureWriteReportData(tpm, reportData); err != nil {
		return nil, err
	}

	hclBlob, err := readNVIndex(tpm, azureHCLReportNVIndex)
	if err != nil {
		return nil, fmt.Errorf("read HCL attestation blob from vTPM: %w", err)
	}

	if len(hclBlob) < azureHCLReportOffset+abi.ReportSize {
		return nil, fmt.Errorf("HCL blob too small: got %d bytes, need at least %d", len(hclBlob), azureHCLReportOffset+abi.ReportSize)
	}

	reportBytes := hclBlob[azureHCLReportOffset : azureHCLReportOffset+abi.ReportSize]
	report, err := abi.ReportToProto(reportBytes)
	if err != nil {
		return nil, fmt.Errorf("parse SNP report: %w", err)
	}

	return &sevsnp.Attestation{Report: report}, nil
}

func azureWriteReportData(t transport.TPM, reportData [64]byte) error {
	_, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(azureReportDataNVIndex)}.Execute(t)
	if err != nil {
		return nil
	}

	nvName, err := nvIndexName(t, azureReportDataNVIndex)
	if err != nil {
		return fmt.Errorf("resolve report data NV index: %w", err)
	}

	_, err = tpm2.NVWrite{
		AuthHandle: ownerAuthHandle(),
		NVIndex:    nvName,
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: reportData[:]},
	}.Execute(t)
	if err != nil {
		return fmt.Errorf("write report data to vTPM NV index 0x%x: %w", azureReportDataNVIndex, err)
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
