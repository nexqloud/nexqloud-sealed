package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"nexqloud-sealed/internal/registry"
	"nexqloud-sealed/internal/rootsecret"
	"nexqloud-sealed/internal/state"
)

const (
	tenantID   = "acme"
	keyVersion = 1
)

func main() {
	registryURL := flag.String("registry", "http://127.0.0.1:7001", "federated registry base URL")
	operators := flag.String("operators", "operator-a,operator-b", "comma-separated operator IDs to wrap for")
	seedHex := flag.String("seed-hex", "", "optional 32-byte seed as hex (generated if empty)")
	flag.Parse()

	chipSecret, err := rootsecret.Chip()
	if err != nil {
		log.Fatalf("chip secret: %v", err)
	}

	seed, generated, err := loadSeed(*seedHex)
	if err != nil {
		log.Fatalf("seed: %v", err)
	}

	wraps := make(map[string][]byte)
	for _, operatorID := range strings.Split(*operators, ",") {
		operatorID = strings.TrimSpace(operatorID)
		if operatorID == "" {
			continue
		}
		wraps[operatorID] = state.Seal(chipSecret, seed)
	}
	if len(wraps) == 0 {
		log.Fatal("no operators specified")
	}

	sum := sha256.Sum256(seed)
	record := registry.CommitmentRecord{
		TenantID:   tenantID,
		KeyVersion: keyVersion,
		SeedCommit: "sha256:" + hex.EncodeToString(sum[:]),
		Wraps:      wraps,
	}

	if err := postRecord(*registryURL, record); err != nil {
		log.Fatalf("post record: %v", err)
	}

	fmt.Printf("posted %s record (key_version=%d) with wraps for %s\n", tenantID, keyVersion, strings.Join(sortedKeys(wraps), ", "))
	fmt.Printf("chip-fingerprint: sha256:%s\n", hex.EncodeToString(chipFingerprint(chipSecret)))
	if generated {
		fmt.Printf("seed-hex (save for other VMs): %s\n", hex.EncodeToString(seed))
	}
}

func loadSeed(seedHex string) ([]byte, bool, error) {
	if seedHex == "" {
		seed := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, seed); err != nil {
			return nil, false, err
		}
		return seed, true, nil
	}

	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, false, fmt.Errorf("decode seed-hex: %w", err)
	}
	if len(seed) != 32 {
		return nil, false, fmt.Errorf("seed-hex length %d, want 32 bytes", len(seed))
	}
	return seed, false, nil
}

func postRecord(registryURL string, record registry.CommitmentRecord) error {
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}

	url := strings.TrimRight(registryURL, "/") + "/records"
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("registry %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func chipFingerprint(chipSecret []byte) []byte {
	sum := sha256.Sum256(chipSecret)
	return sum[:]
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}
