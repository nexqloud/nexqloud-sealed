package enclave

import (
	"fmt"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func azureRequestReport(reportData [64]byte) (*sevsnp.Attestation, error) {
	tpm, err := openAzureTPM()
	if err != nil {
		return nil, err
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
	return writeNVIndex(t, azureReportDataNVIndex, reportData[:])
}
