//go:build js && wasm

package verify

type HardwareRoots struct {
	ProductLine string
	ASK         []byte
	ARK         []byte
}
