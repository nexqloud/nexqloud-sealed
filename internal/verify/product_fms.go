package verify

import (
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
)

// ProductLineFromFms maps CPUID_1_EAX family/model/stepping to the AMD KDS
// product line used for VCEK URLs and ASK/ARK roots.
//
// Siena (EPYC 8004, family 19h model A0h) shares Genoa's ARK/ASK and KDS
// serves its VCEKs under the Genoa product path.
func ProductLineFromFms(fms uint32) string {
	family, model, _ := abi.FmsFromCpuid1Eax(fms)
	if family == 0x19 && model == 0xa0 {
		return "Genoa"
	}
	return kds.ProductLineFromFms(fms)
}
