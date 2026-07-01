package destruction

import (
	"sort"

	"nexqloud-sealed/internal/registry"
)

func Quorum(reg registry.Client, tenantID string) ([]string, error) {
	rec, err := reg.Get(tenantID)
	if err != nil {
		return nil, err
	}
	ops := make([]string, 0, len(rec.Wraps))
	for opID := range rec.Wraps {
		ops = append(ops, opID)
	}
	sort.Strings(ops)
	return ops, nil
}
