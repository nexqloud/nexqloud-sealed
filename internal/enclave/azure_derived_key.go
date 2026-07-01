package enclave

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/google/go-sev-guest/abi"
)

const (
	azureHCLRequestTypeAttestation = 2
	azureDerivedKeyRespSize        = 64
)

func AzureRequestDerivedKey() ([]byte, error) {
	if key, err := azureDerivedKeyViaHCLExchange(); err == nil {
		return key, nil
	}
	return azureChipFromBootReport()
}

func azureDerivedKeyViaHCLExchange() ([]byte, error) {
	tpm, err := openAzureTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	if err := writeNVIndex(tpm, azureReportDataNVIndex, derivedKeyRequestNVData()); err != nil {
		return nil, fmt.Errorf("write derived key request to vTPM nv 0x%x: %w", azureReportDataNVIndex, err)
	}

	blob, err := readNVIndex(tpm, azureHCLReportNVIndex)
	if err != nil {
		return nil, fmt.Errorf("read derived key response from vTPM nv 0x%x: %w", azureHCLReportNVIndex, err)
	}

	return parseDerivedKeyFromHCLBlob(blob)
}

func azureChipFromBootReport() ([]byte, error) {
	tpm, err := openAzureTPM()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	blob, err := readNVIndex(tpm, azureHCLReportNVIndex)
	if err != nil {
		return nil, fmt.Errorf("read HCL boot report from vTPM: %w", err)
	}
	if len(blob) < azureHCLReportOffset+abi.ReportSize {
		return nil, fmt.Errorf("HCL boot report too small: got %d bytes, need at least %d", len(blob), azureHCLReportOffset+abi.ReportSize)
	}

	reportBytes := blob[azureHCLReportOffset : azureHCLReportOffset+abi.ReportSize]
	report, err := abi.ReportToProto(reportBytes)
	if err != nil {
		return nil, fmt.Errorf("parse SNP report from HCL boot blob: %w", err)
	}

	measurement := report.GetMeasurement()
	if len(measurement) == 0 {
		return nil, fmt.Errorf("SNP report missing measurement")
	}
	sum := sha256.Sum256(measurement)
	return sum[:], nil
}

func parseDerivedKeyFromHCLBlob(blob []byte) ([]byte, error) {
	if key, ok := parseSnpDerivedKeyResp(blob); ok {
		return key, nil
	}
	if len(blob) > azureHCLReportOffset {
		if key, ok := parseSnpDerivedKeyResp(blob[azureHCLReportOffset:]); ok {
			return key, nil
		}
	}
	if len(blob) >= azureHCLReportOffset+azureDerivedKeyRespSize {
		if key, ok := parseSnpDerivedKeyResp(blob[azureHCLReportOffset : azureHCLReportOffset+azureDerivedKeyRespSize]); ok {
			return key, nil
		}
	}
	if len(blob) >= 4 {
		reqType := binary.LittleEndian.Uint32(blob[12:16])
		if reqType != azureHCLRequestTypeAttestation {
			return nil, fmt.Errorf("unexpected HCL request type 0x%x in derived key response", reqType)
		}
	}
	return nil, fmt.Errorf("derived key not present in HCL vTPM response (%d bytes)", len(blob))
}

func parseSnpDerivedKeyResp(blob []byte) ([]byte, bool) {
	if len(blob) < azureDerivedKeyRespSize {
		return nil, false
	}
	if binary.LittleEndian.Uint32(blob[:4]) != 0 {
		return nil, false
	}
	return append([]byte(nil), blob[32:64]...), true
}
