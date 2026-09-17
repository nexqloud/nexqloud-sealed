package registry

type CommitmentRecord struct {
	TenantID   string            `json:"tenant_id"`
	KeyVersion int               `json:"key_version"`
	SeedCommit string            `json:"seed_commit"`
	Wraps      map[string][]byte `json:"wraps"`
	// Callbacks maps an operator to the URL a coordinator can reach it on for
	// destruction, so deployments self-register instead of being hand-added to a
	// coordinator's operator map.
	Callbacks map[string]string `json:"callbacks,omitempty"`
}
