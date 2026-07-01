package destroy

import (
	"fmt"

	"nexqloud-sealed/internal/identity"
	"nexqloud-sealed/internal/seen"
)

type DeleteRequest struct {
	TenantID    string `json:"tenant_id"`
	CustomerSig []byte `json:"customer_sig"`
	Nonce       string `json:"nonce"`
}

func Accept(req DeleteRequest, jwksURL string) error {
	if err := identity.VerifySig(req.CustomerSig, req.TenantID, jwksURL); err != nil {
		return fmt.Errorf("unauthorized deletion: %w", err)
	}
	if err := seen.Once(req.Nonce); err != nil {
		return fmt.Errorf("unauthorized deletion: %w", err)
	}
	return nil
}
