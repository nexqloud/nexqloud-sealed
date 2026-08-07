//go:build !(js && wasm)

package enclave

import (
	"crypto/ed25519"
	"fmt"
	"sync"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/sevsnp"
	sevverify "github.com/google/go-sev-guest/verify"
	"google.golang.org/protobuf/proto"
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
	var lastErr error
	for _, product := range kdsProductCandidates(att) {
		line := kds.ProductLine(product)
		report, ok := proto.Clone(att.Report).(*sevsnp.Report)
		if !ok || report == nil {
			return nil, "", fmt.Errorf("clone attestation report")
		}
		// go-sev-guest prefers report FMS over Options.Product when FMS != 0.
		// Clear it so the candidate product actually drives the KDS URL.
		report.Cpuid1EaxFms = 0

		opts := sevverify.DefaultOptions()
		opts.Product = product
		filled, err := sevverify.GetAttestationFromReport(report, opts)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", line, err)
			continue
		}
		if hasVCEK(filled.CertificateChain) {
			return filled, line, nil
		}
		lastErr = fmt.Errorf("%s: missing VCEK", line)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no AMD SEV product candidates")
	}
	return nil, "", fmt.Errorf("fetch certificates from AMD KDS: %w", lastErr)
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
			add(abi.SevProductFromCpuid1Eax(fms))
		}
	}
	if att != nil {
		add(att.Product)
	}
	add(abi.SevProduct())

	// Kata guests often expose an unmapped FMS/CPUID even on real EPYC hosts.
	// Probe the known KDS product lines; the matching VCEK URL succeeds.
	for _, line := range []string{"Milan", "Genoa", "Turin"} {
		if p, err := kds.ParseProductLine(line); err == nil {
			add(p)
		}
	}
	return out
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
