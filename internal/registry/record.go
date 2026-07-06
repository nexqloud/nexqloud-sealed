package registry

type CommitmentRecord struct {
	TenantID   string            `json:"tenant_id"`
	KeyVersion int               `json:"key_version"`
	SeedCommit string            `json:"seed_commit"`
	Wraps      map[string][]byte `json:"wraps"`
}
