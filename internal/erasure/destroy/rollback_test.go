package destroy_test

import (
	"testing"

	"nexqloud-sealed/internal/erasure/destroy"
)

func TestAntiRollbackZeroizesChipAndRotatesSalt(t *testing.T) {
	chip := []byte("chip-secret-32-bytes-long!!!!!!")
	path := t.TempDir() + "/federation_salt.json"

	roll, err := destroy.AntiRollback(chip, path, "acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	if roll.PreviousEpoch != 1 || roll.SaltEpoch < 2 {
		t.Fatalf("expected salt epoch 1 -> >=2, got %d -> %d", roll.PreviousEpoch, roll.SaltEpoch)
	}
	if !roll.ChipZeroized {
		t.Fatal("anti-rollback did not report the chip material as zeroized")
	}
	if roll.MarkLogIndex != "" {
		t.Fatalf("unsigned mark must not produce a log index, got %q", roll.MarkLogIndex)
	}
	for _, b := range chip {
		if b != 0 {
			t.Fatal("chip secret was not zeroized")
		}
	}

	roll2, err := destroy.AntiRollback(make([]byte, 32), path, "acme", nil)
	if err != nil {
		t.Fatal(err)
	}
	if roll2.SaltEpoch != roll.SaltEpoch+1 {
		t.Fatalf("epoch2=%d epoch1=%d", roll2.SaltEpoch, roll.SaltEpoch)
	}
}

func TestAntiRollbackRejectsMissingChipSecret(t *testing.T) {
	if _, err := destroy.AntiRollback(nil, t.TempDir()+"/federation_salt.json", "acme", nil); err == nil {
		t.Fatal("expected an error for a missing chip secret")
	}
}
