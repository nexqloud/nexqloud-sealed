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
