package verify

import iv "nexqloud-sealed/internal/verify"

type HardwareRoots struct {
	ProductLine string
	ASK         []byte
	ARK         []byte
}

func (r HardwareRoots) internal() iv.HardwareRoots {
	return iv.HardwareRoots{
		ProductLine: r.ProductLine,
		ASK:         r.ASK,
		ARK:         r.ARK,
	}
}
