//go:build js && wasm

package main

import "nexqloud-sealed/pkg/verify"

func loadHardwareRootsCatalog() (map[string]verify.HardwareRoots, error) {
	return verify.LoadHardwareRootsCatalog()
}
