package wipe_test

import (
	"testing"

	"nexqloud-sealed/internal/gpu/wipe"
)

func TestTwoPassHostBuffer(t *testing.T) {
	t.Setenv("WIPE_MODE", wipe.ModeHostBuffer)
	if err := wipe.TwoPass(); err != nil {
		t.Fatal(err)
	}
}
