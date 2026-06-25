package enclave

import (
	"crypto/ed25519"
	"fmt"
	"sync"

	"github.com/google/go-sev-guest/proto/sevsnp"
	sevverify "github.com/google/go-sev-guest/verify"
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

	filled, err := sevverify.GetAttestationFromReport(att.Report, sevverify.DefaultOptions())
	if err != nil {
		return fmt.Errorf("fetch certificates from AMD KDS: %w", err)
	}
	if filled.CertificateChain == nil || !hasVCEK(filled.CertificateChain) {
		return fmt.Errorf("AMD KDS returned attestation without VCEK certificate")
	}

	hardwareCertCache.mu.Lock()
	hardwareCertCache.chain = cloneCertificateChain(filled.CertificateChain)
	hardwareCertCache.mu.Unlock()
	return nil
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
