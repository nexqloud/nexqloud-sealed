//go:build js && wasm

package main

import (
	_ "embed"
	"fmt"

	"github.com/google/go-sev-guest/kds"

	"nexqloud-sealed/pkg/verify"
)

//go:embed certs/ask_ark_milan.pem
var askArkMilan []byte

//go:embed certs/ask_ark_genoa.pem
var askArkGenoa []byte

//go:embed certs/ask_ark_turin_vcek.pem
var askArkTurin []byte

func loadHardwareRootsCatalog() (map[string]verify.HardwareRoots, error) {
	bundles := map[string][]byte{
		"Milan": askArkMilan,
		"Genoa": askArkGenoa,
		"Turin": askArkTurin,
	}

	out := make(map[string]verify.HardwareRoots, len(bundles))
	for product, pem := range bundles {
		ask, ark, err := kds.ParseProductCertChain(pem)
		if err != nil {
			return nil, fmt.Errorf("parse %s ASK/ARK bundle: %w", product, err)
		}
		out[product] = verify.HardwareRoots{
			ProductLine: product,
			ASK:         ask,
			ARK:         ark,
		}
	}
	return out, nil
}
