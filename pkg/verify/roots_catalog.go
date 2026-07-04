package verify

import (
	_ "embed"
	"fmt"

	"github.com/google/go-sev-guest/kds"
)

//go:embed certs/ask_ark_milan.pem
var askArkMilan []byte

//go:embed certs/ask_ark_genoa.pem
var askArkGenoa []byte

//go:embed certs/ask_ark_turin_vcek.pem
var askArkTurin []byte

func LoadHardwareRootsCatalog() (map[string]HardwareRoots, error) {
	bundles := map[string][]byte{
		"Milan": askArkMilan,
		"Genoa": askArkGenoa,
		"Turin": askArkTurin,
	}

	out := make(map[string]HardwareRoots, len(bundles))
	for product, pem := range bundles {
		ask, ark, err := kds.ParseProductCertChain(pem)
		if err != nil {
			return nil, fmt.Errorf("parse %s ASK/ARK bundle: %w", product, err)
		}
		out[product] = HardwareRoots{
			ProductLine: product,
			ASK:         ask,
			ARK:         ark,
		}
	}
	return out, nil
}

func ApplyCustomHardwareRoots(catalog map[string]HardwareRoots, productLine string, ask, ark []byte) map[string]HardwareRoots {
	if len(ask) == 0 && len(ark) == 0 {
		return catalog
	}
	if catalog == nil {
		catalog = make(map[string]HardwareRoots)
	}
	catalog[productLine] = HardwareRoots{
		ProductLine: productLine,
		ASK:         ask,
		ARK:         ark,
	}
	return catalog
}
