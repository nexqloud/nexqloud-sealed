package destruction

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestMerkleRootDeterministic(t *testing.T) {
	a, _ := hex.DecodeString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	b, _ := hex.DecodeString("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	root := merkleRoot([][]byte{a, b})
	if len(root) != sha256.Size {
		t.Fatalf("root len = %d", len(root))
	}

	root2 := merkleRoot([][]byte{a, b})
	if hex.EncodeToString(root) != hex.EncodeToString(root2) {
		t.Fatal("merkle root not deterministic")
	}
}

func TestMerkleRootOddLeaves(t *testing.T) {
	a := []byte{1, 2, 3}
	b := []byte{4, 5, 6}
	c := []byte{7, 8, 9}
	root := merkleRoot([][]byte{a, b, c})
	if len(root) != sha256.Size {
		t.Fatalf("root len = %d", len(root))
	}
}
