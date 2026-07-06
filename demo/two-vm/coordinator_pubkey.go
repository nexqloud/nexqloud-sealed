package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: coordinator_pubkey.go <64-byte-seed-hex>")
		os.Exit(1)
	}
	seed, err := hex.DecodeString(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(seed) != ed25519.SeedSize {
		fmt.Fprintf(os.Stderr, "seed length %d, want %d\n", len(seed), ed25519.SeedSize)
		os.Exit(1)
	}
	sk := ed25519.NewKeyFromSeed(seed)
	fmt.Print(hex.EncodeToString(sk.Public().(ed25519.PublicKey)))
}
