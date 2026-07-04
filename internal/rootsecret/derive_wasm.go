//go:build js && wasm

package rootsecret

import "fmt"

func Chip() ([]byte, error) {
	return nil, fmt.Errorf("chip secret derivation unavailable in wasm build")
}
