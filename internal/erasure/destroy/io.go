package destroy

import (
	"crypto/rand"
	"os"
)

func randRead(b []byte) (int, error) {
	return rand.Read(b)
}

func mkdirAll(path string) error {
	return os.MkdirAll(path, 0o700)
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

// allZero reports whether a buffer currently holds no non-zero byte. An empty
// buffer is not evidence of erasure, so it reports false.
func allZero(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
