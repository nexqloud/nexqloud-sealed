//go:build !(js && wasm)

package verify

import (
	"fmt"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/sevsnp"
	sevverify "github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

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

	report, cloned := proto.Clone(att.Report).(*sevsnp.Report)
	if !cloned || report == nil {
		return fail("clone attestation report")
	}

	productLine := roots.ProductLine
	if productLine == "" {
		if fms := report.GetCpuid1EaxFms(); fms != 0 {
			productLine = ProductLineFromFms(fms)
		}
	}
	if productLine == "Unknown" {
		productLine = ""
	}

	opts := sevverify.DefaultOptions()
	opts.DisableCertFetching = true

	// go-sev-guest keys TrustedRoots / embedded ARK/ASK by kds.ProductLineFromFms,
	// which does not know Siena. Rewrite FMS to the KDS product (Genoa for Siena)
	// so root lookup and VCEK productName validation succeed.
	if productLine != "" {
		product, err := kds.ParseProductLine(productLine)
		if err != nil {
			return fail("hardware-chain: " + err.Error())
		}
		if fms := report.GetCpuid1EaxFms(); fms != 0 {
			_, _, stepping := abi.FmsFromCpuid1Eax(fms)
			product.MachineStepping = wrapperspb.UInt32(uint32(stepping))
		}
		report.Cpuid1EaxFms = abi.MaskedCpuid1EaxFromSevProduct(product)
		opts.Product = product
	}

	full := &sevsnp.Attestation{
		Report:           report,
		CertificateChain: protoChain,
	}

	if len(roots.ASK) > 0 && len(roots.ARK) > 0 {
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
		line := ProductLineFromFms(fms)
		if line == "" || line == "Unknown" {
			return "", fmt.Errorf("unsupported AMD SEV product for FMS 0x%x", fms)
		}
		return line, nil
	}
	return "", fmt.Errorf("report does not include CPU product information")
}
