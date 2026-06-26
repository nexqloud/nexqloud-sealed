//go:build !(js && wasm)

package verify

import (
	"fmt"

	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/sevsnp"
	sevverify "github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"

	"nexqloud-sealed/internal/receipt"
)

type HardwareRoots struct {
	ProductLine string
	ASK         []byte
	ARK         []byte
}

func VerifyHardwareChain(att *sevsnp.Attestation, chain receipt.CertificateChain, roots HardwareRoots) Result {
	if att == nil || att.Report == nil {
		return fail("missing-attestation")
	}

	protoChain, err := receipt.DecodeCertificateChain(chain)
	if err != nil {
		return fail("cert-chain-decode: " + err.Error())
	}

	full := &sevsnp.Attestation{
		Report:           att.Report,
		CertificateChain: protoChain,
	}

	opts := sevverify.DefaultOptions()
	opts.DisableCertFetching = true

	if len(roots.ASK) > 0 && len(roots.ARK) > 0 {
		productLine := roots.ProductLine
		if productLine == "" {
			if fms := att.Report.GetCpuid1EaxFms(); fms != 0 {
				productLine = kds.ProductLineFromFms(fms)
			}
		}
		if productLine == "" {
			return fail("hardware-chain: missing product line for custom AMD roots")
		}

		root := trust.AMDRootCertsProduct(productLine)
		if err := root.Decode(roots.ASK, roots.ARK); err != nil {
			return fail("amd-root-decode: " + err.Error())
		}
		opts.TrustedRoots = map[string][]*trust.AMDRootCerts{
			productLine: {root},
		}
	}

	if err := sevverify.SnpAttestation(full, opts); err != nil {
		return fail("hardware-chain: " + err.Error())
	}

	return ok()
}

func ProductLineFromReport(att *sevsnp.Attestation) (string, error) {
	if att == nil || att.Report == nil {
		return "", fmt.Errorf("missing attestation report")
	}
	if fms := att.Report.GetCpuid1EaxFms(); fms != 0 {
		return kds.ProductLineFromFms(fms), nil
	}
	return "", fmt.Errorf("report does not include CPU product information")
}
