package destruction

import (
	"fmt"

	"nexqloud-sealed/internal/identity"
	"nexqloud-sealed/internal/seen"
)

func acceptDeleteRequest(tenantID string, customerSig []byte, nonce, jwksURL string) error {
	if err := identity.VerifySig(customerSig, tenantID, jwksURL); err != nil {
		return fmt.Errorf("unauthorized deletion: %w", err)
	}
	if err := seen.Once(nonce); err != nil {
		return fmt.Errorf("unauthorized deletion: %w", err)
	}
	return nil
}

func WrapEvidence(wrap []byte) string {
	return evidenceOf(wrap)
}
