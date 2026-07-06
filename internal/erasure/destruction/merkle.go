package destruction

import (
	"crypto/sha256"
)

func merkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}
	level := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		dup := make([]byte, len(leaf))
		copy(dup, leaf)
		level[i] = dup
	}

	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			sum := sha256.Sum256(append(level[i], level[i+1]...))
			next = append(next, sum[:])
		}
		level = next
	}
	return level[0]
}
