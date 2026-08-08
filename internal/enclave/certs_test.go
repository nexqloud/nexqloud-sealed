//go:build !(js && wasm)

package enclave

import (
	"sync"
	"testing"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
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

func TestSevProductFromFmsSienaMapsToGenoa(t *testing.T) {
	fms := abi.FmsToCpuid1Eax(0x19, 0xa0, 2)
	p := sevProductFromFms(fms)
	if p == nil {
		t.Fatal("expected Genoa product for Siena FMS")
	}
	if got := kds.ProductLine(p); got != "Genoa" {
		t.Fatalf("product line = %q, want Genoa", got)
	}
	if p.MachineStepping == nil || p.MachineStepping.Value != 2 {
		t.Fatalf("stepping = %v, want 2", p.MachineStepping)
	}
}

func TestKdsProductCandidatesPrefersSienaAsGenoa(t *testing.T) {
	fms := abi.FmsToCpuid1Eax(0x19, 0xa0, 2)
	candidates := kdsProductCandidates(&sevsnp.Attestation{
		Report: &sevsnp.Report{Cpuid1EaxFms: fms},
	})
	if len(candidates) == 0 {
		t.Fatal("expected candidates")
	}
	if got := kds.ProductLine(candidates[0]); got != "Genoa" {
		t.Fatalf("first candidate = %q, want Genoa", got)
	}
}
