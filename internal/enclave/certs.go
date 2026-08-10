//go:build !(js && wasm)

package enclave

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/sevsnp"
	sevverify "github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var hardwareCertCache = struct {
	mu    sync.RWMutex
	chain *sevsnp.CertificateChain
	once  sync.Once
	err   error
}{}

func WarmCertificateCache(pub ed25519.PublicKey) error {
	hardwareCertCache.once.Do(func() {
		hardwareCertCache.err = fetchAndStoreCertificateChain(pub)
	})
	return hardwareCertCache.err
}

func fetchAndStoreCertificateChain(pub ed25519.PublicKey) error {
	nonce := make([]byte, 32)
	att, err := requestHardwareReport(pub, nonce)
	if err != nil {
		return fmt.Errorf("warmup attestation report: %w", err)
	}

	if hasFullChain(att.CertificateChain) {
		hardwareCertCache.mu.Lock()
		hardwareCertCache.chain = cloneCertificateChain(att.CertificateChain)
		hardwareCertCache.mu.Unlock()
		return nil
	}

	filled, productLine, err := fetchCertificatesFromKDS(att)
	if err != nil {
		return err
	}
	if filled.CertificateChain == nil || !hasVCEK(filled.CertificateChain) {
		return fmt.Errorf("AMD KDS returned attestation without VCEK certificate (%s)", productLine)
	}

	hardwareCertCache.mu.Lock()
	hardwareCertCache.chain = cloneCertificateChain(filled.CertificateChain)
	hardwareCertCache.mu.Unlock()
	return nil
}

func fetchCertificatesFromKDS(att *sevsnp.Attestation) (*sevsnp.Attestation, string, error) {
	var errs []error
	for _, product := range kdsProductCandidates(att) {
		line := kds.ProductLine(product)
		report, ok := proto.Clone(att.Report).(*sevsnp.Report)
		if !ok || report == nil {
			return nil, "", fmt.Errorf("clone attestation report")
		}
		// go-sev-guest prefers report FMS over Options.Product when FMS != 0.
		// Force the candidate's canonical FMS so the product line drives the
		// KDS URL and the post-download VCEK productName check is skipped.
		// Clearing FMS instead trips ParseProductName on Siena VCEKs, which
		// carry productName "Genoa" without a -Bx stepping suffix.
		report.Cpuid1EaxFms = abi.MaskedCpuid1EaxFromSevProduct(product)

		opts := sevverify.DefaultOptions()
		opts.Product = product
		// DefaultHTTPSGetter retries for 2m per URL; wrong product lines 404
		// and would block warmup for minutes. Keep retries short for probes.
		opts.Getter = &trust.RetryHTTPSGetter{
			Timeout:       20 * time.Second,
			MaxRetryDelay: 2 * time.Second,
			Getter:        &trust.SimpleHTTPSGetter{},
		}
		log.Printf("KDS: fetching certificate chain for product line %s", line)
		filled, err := sevverify.GetAttestationFromReport(report, opts)
		if err != nil {
			log.Printf("KDS: %s failed: %v", line, err)
			errs = append(errs, fmt.Errorf("%s: %w", line, err))
			continue
		}
		if hasVCEK(filled.CertificateChain) {
			log.Printf("KDS: %s ok", line)
			return filled, line, nil
		}
		errs = append(errs, fmt.Errorf("%s: missing VCEK", line))
	}
	if len(errs) == 0 {
		errs = append(errs, fmt.Errorf("no AMD SEV product candidates"))
	}
	return nil, "", fmt.Errorf("fetch certificates from AMD KDS: %w", errors.Join(errs...))
}

func kdsProductCandidates(att *sevsnp.Attestation) []*sevsnp.SevProduct {
	seen := map[string]struct{}{}
	var out []*sevsnp.SevProduct
	add := func(p *sevsnp.SevProduct) {
		if p == nil {
			return
		}
		line := kds.ProductLine(p)
		if line == "Unknown" {
			return
		}
		if _, ok := seen[line]; ok {
			return
		}
		seen[line] = struct{}{}
		out = append(out, p)
	}

	if att != nil && att.Report != nil {
		if fms := att.Report.GetCpuid1EaxFms(); fms != 0 {
			add(sevProductFromFms(fms))
		}
	}
	if att != nil {
		add(att.Product)
	}
	add(abi.SevProduct())

	// Prefer Genoa first: Siena hosts are served under Genoa KDS paths, and
	// Kata guests often expose an unmapped FMS. Wrong lines 404; order matters.
	for _, line := range []string{"Genoa", "Turin", "Milan"} {
		if p, err := kds.ParseProductLine(line); err == nil {
			add(p)
		}
	}
	return preferProductLine(out, "Genoa")
}

func preferProductLine(in []*sevsnp.SevProduct, line string) []*sevsnp.SevProduct {
	var first, rest []*sevsnp.SevProduct
	for _, p := range in {
		if kds.ProductLine(p) == line {
			first = append(first, p)
		} else {
			rest = append(rest, p)
		}
	}
	return append(first, rest...)
}

// sevProductFromFms maps report CPUID FMS to a SevProduct for KDS lookups.
// Siena (family 19h, model A0h) is remapped to Genoa because AMD serves
// Siena VCEKs under the Genoa product path and shares Genoa ARK/ASK.
func sevProductFromFms(fms uint32) *sevsnp.SevProduct {
	family, model, stepping := abi.FmsFromCpuid1Eax(fms)
	if family == 0x19 && model == 0xa0 {
		p, err := kds.ParseProductLine("Genoa")
		if err != nil {
			return nil
		}
		p.MachineStepping = wrapperspb.UInt32(uint32(stepping))
		return p
	}
	return abi.SevProductFromCpuid1Eax(fms)
}

func AttachCertificateChain(att *sevsnp.Attestation) error {
	if att == nil || att.Report == nil {
		return fmt.Errorf("missing attestation report")
	}
	if hasVCEK(att.CertificateChain) {
		return nil
	}

	chain, err := cachedCertificateChain()
	if err != nil {
		return err
	}

	att.CertificateChain = chain
	return nil
}

func cachedCertificateChain() (*sevsnp.CertificateChain, error) {
	hardwareCertCache.mu.RLock()
	defer hardwareCertCache.mu.RUnlock()

	if hardwareCertCache.chain == nil {
		return nil, fmt.Errorf("certificate cache not warmed; call WarmCertificateCache at startup")
	}

	return cloneCertificateChain(hardwareCertCache.chain), nil
}

func cloneCertificateChain(chain *sevsnp.CertificateChain) *sevsnp.CertificateChain {
	if chain == nil {
		return nil
	}

	out := &sevsnp.CertificateChain{
		VcekCert:     append([]byte(nil), chain.VcekCert...),
		VlekCert:     append([]byte(nil), chain.VlekCert...),
		AskCert:      append([]byte(nil), chain.AskCert...),
		ArkCert:      append([]byte(nil), chain.ArkCert...),
		FirmwareCert: append([]byte(nil), chain.FirmwareCert...),
	}
	if len(chain.Extras) > 0 {
		out.Extras = make(map[string][]byte, len(chain.Extras))
		for key, value := range chain.Extras {
			out.Extras[key] = append([]byte(nil), value...)
		}
	}
	return out
}

func hasVCEK(chain *sevsnp.CertificateChain) bool {
	return chain != nil && len(chain.VcekCert) > 0
}

func hasFullChain(chain *sevsnp.CertificateChain) bool {
	return hasVCEK(chain) && len(chain.AskCert) > 0 && len(chain.ArkCert) > 0
}
