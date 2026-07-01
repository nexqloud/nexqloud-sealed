package kdf_test

import (
	"bytes"
	"testing"

	"nexqloud-sealed/internal/kdf"
)

func TestRotateFederationSaltChangesDEK(t *testing.T) {
	path := t.TempDir() + "/federation_salt.json"
	seed := bytes.Repeat([]byte{1}, 32)
	chip := bytes.Repeat([]byte{2}, 32)
	claim := bytes.Repeat([]byte{3}, 32)
	bind := []byte("bind")

	salt1, epoch1, err := kdf.FederationSaltBytes(path)
	if err != nil {
		t.Fatal(err)
	}
	dek1, err := kdf.DeriveDEKWithFederation(seed, chip, claim, bind, "acme", 1, salt1, epoch1)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = kdf.RotateFederationSalt(path)
	if err != nil {
		t.Fatal(err)
	}
	salt2, epoch2, err := kdf.FederationSaltBytes(path)
	if err != nil {
		t.Fatal(err)
	}
	dek2, err := kdf.DeriveDEKWithFederation(seed, chip, claim, bind, "acme", 1, salt2, epoch2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dek1, dek2) {
		t.Fatal("expected DEK to change after salt rotation")
	}
}
