//go:build js && wasm

package verify

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"

	"nexqloud-sealed/internal/receipt"
)

func VerifyHardwareChain(att *sevsnp.Attestation, chain receipt.CertificateChain, roots HardwareRoots) Result {
	if att == nil || att.Report == nil {
		return fail("missing-attestation")
	}

	protoChain, err := receipt.DecodeCertificateChain(chain)
	if err != nil {
		return fail("cert-chain-decode: " + err.Error())
	}

	vcek, err := parseCert(protoChain.VcekCert)
	if err != nil {
		return fail("vcek-parse: " + err.Error())
	}

	if len(roots.ASK) == 0 || len(roots.ARK) == 0 {
		return fail("hardware-chain: missing embedded AMD ASK/ARK roots")
	}

	askRoot, err := parseCert(roots.ASK)
	if err != nil {
		return fail("ask-root-parse: " + err.Error())
	}
	arkRoot, err := parseCert(roots.ARK)
	if err != nil {
		return fail("ark-root-parse: " + err.Error())
	}

	intermediates := x509.NewCertPool()
	if len(protoChain.AskCert) > 0 {
		askIntermediate, err := parseCert(protoChain.AskCert)
		if err != nil {
			return fail("ask-intermediate-parse: " + err.Error())
		}
		intermediates.AddCert(askIntermediate)
	} else {
		intermediates.AddCert(askRoot)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(arkRoot)

	now := time.Now()
	if _, err := vcek.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediates,
		CurrentTime:   now,
	}); err != nil {
		return fail("hardware-chain: " + err.Error())
	}

	if err := verifyReportSignature(att.Report, vcek); err != nil {
		return fail("hardware-chain: " + err.Error())
	}

	return ok()
}

func parseCert(der []byte) (*x509.Certificate, error) {
	raw := der
	if block, _ := pem.Decode(der); block != nil {
		raw = block.Bytes
	}
	return x509.ParseCertificate(raw)
}

func verifyReportSignature(report *sevsnp.Report, vcek *x509.Certificate) error {
	raw, err := abi.ReportToAbiBytes(report)
	if err != nil {
		return fmt.Errorf("could not interpret report: %w", err)
	}
	if err := abi.ValidateReportFormat(raw); err != nil {
		return fmt.Errorf("attestation report format error: %w", err)
	}
	der, err := abi.ReportToSignatureDER(raw)
	if err != nil {
		return fmt.Errorf("could not interpret report signature: %w", err)
	}
	if abi.SignatureAlgo(raw) == abi.SignEcdsaP384Sha384 {
		if err := vcek.CheckSignature(x509.ECDSAWithSHA384, abi.SignedComponent(raw), der); err != nil {
			return fmt.Errorf("report signature verification error: %w", err)
		}
		return nil
	}
	return fmt.Errorf("unknown SignatureAlgo: %d", abi.SignatureAlgo(raw))
}
