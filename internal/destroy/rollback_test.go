package destroy_test

import (
	"testing"

	"nexqloud-sealed/internal/destroy"
)

func TestAntiRollbackZeroizesChipAndRotatesSalt(t *testing.T) {
	chip := []byte("chip-secret-32-bytes-long!!!!!!")
	path := t.TempDir() + "/federation_salt.json"

	epoch1, err := destroy.AntiRollback(chip, path)
	if err != nil {
		t.Fatal(err)
	}
	if epoch1 < 2 {
		t.Fatalf("expected rotated epoch >= 2, got %d", epoch1)
	}
	for _, b := range chip {
		if b != 0 {
			t.Fatal("chip secret was not zeroized")
		}
	}

	epoch2, err := destroy.AntiRollback(make([]byte, 32), path)
	if err != nil {
		t.Fatal(err)
	}
	if epoch2 != epoch1+1 {
		t.Fatalf("epoch2=%d epoch1=%d", epoch2, epoch1)
	}
}
