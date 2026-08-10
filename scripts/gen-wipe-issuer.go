//go:build ignore

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func main() {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	seed := priv.Seed()
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Printf("WIPE_ISSUER_PRIVKEY=%s\n", hex.EncodeToString(seed))
	fmt.Printf("pubkey=%s\n", hex.EncodeToString(pub))
	fmt.Println("Put pubkey in web/sealed-wipe-issuers/{env}/allowlist.json")
	fmt.Println("Set WIPE_ISSUER_PRIVKEY on the wipe-worker host (do not commit the seed).")
}
