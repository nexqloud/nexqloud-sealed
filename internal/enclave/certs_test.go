package enclave

import (
	"sync"
	"testing"

	"github.com/google/go-sev-guest/proto/sevsnp"
)

func TestCloneCertificateChainIsIndependent(t *testing.T) {
	original := &sevsnp.CertificateChain{
		VcekCert: []byte{1, 2, 3},
		AskCert:  []byte{4, 5},
		ArkCert:  []byte{6, 7, 8},
	}

	clone := cloneCertificateChain(original)
	clone.VcekCert[0] = 99

	if original.VcekCert[0] == 99 {
		t.Fatal("clone mutated cached certificate bytes")
	}
}

func TestCachedCertificateChainRequiresWarm(t *testing.T) {
	hardwareCertCache.mu.Lock()
	hardwareCertCache.chain = nil
	hardwareCertCache.once = sync.Once{}
	hardwareCertCache.err = nil
	hardwareCertCache.mu.Unlock()

	if _, err := cachedCertificateChain(); err == nil {
		t.Fatal("expected error when cache is not warmed")
	}
}
