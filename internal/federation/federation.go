package federation

import "sync"

var (
	mu       sync.RWMutex
	excluded = make(map[string]map[string]struct{})
)

func Exclude(opID, tenantID string) {
	mu.Lock()
	defer mu.Unlock()
	if excluded[tenantID] == nil {
		excluded[tenantID] = make(map[string]struct{})
	}
	excluded[tenantID][opID] = struct{}{}
}

func IsExcluded(opID, tenantID string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, ok := excluded[tenantID][opID]
	return ok
}

func FilterQualified(ops []string, tenantID string) []string {
	mu.RLock()
	defer mu.RUnlock()
	set := excluded[tenantID]
	if len(set) == 0 {
		return ops
	}
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		if _, dropped := set[op]; !dropped {
			out = append(out, op)
		}
	}
	return out
}

func Reset() {
	mu.Lock()
	defer mu.Unlock()
	excluded = make(map[string]map[string]struct{})
}
