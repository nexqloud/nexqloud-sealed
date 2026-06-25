package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

func Commitment(dir string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.safetensors"))
	if err != nil {
		return "", fmt.Errorf("glob safetensors: %w", err)
	}

	sort.Strings(matches)
	if len(matches) == 0 {
		return "", fmt.Errorf("no *.safetensors files found in %s", dir)
	}

	h := sha256.New()
	for _, path := range matches {
		f, err := os.Open(path)
		if err != nil {
			return "", fmt.Errorf("open %s: %w", path, err)
		}

		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			return "", fmt.Errorf("read %s: %w", path, err)
		}
		if err := f.Close(); err != nil {
			return "", fmt.Errorf("close %s: %w", path, err)
		}
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
