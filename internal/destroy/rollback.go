package destroy

import (
	"fmt"

	"nexqloud-sealed/internal/kdf"
)

func AntiRollback(chipSecret []byte, saltPath string) (saltEpoch int, err error) {
	if len(chipSecret) == 0 {
		return 0, fmt.Errorf("missing chip secret")
	}
	zeroize(chipSecret)

	epoch, _, err := kdf.RotateFederationSalt(saltPath)
	if err != nil {
		return 0, fmt.Errorf("rotate federation salt: %w", err)
	}
	return epoch, nil
}
