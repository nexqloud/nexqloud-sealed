package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"nexqloud-sealed/internal/destruction"
	pkgverify "nexqloud-sealed/pkg/verify"
)

func main() {
	registryURL := flag.String("registry", "http://127.0.0.1:7001", "federated registry base URL")
	tenantID := flag.String("tenant", "acme", "tenant id for registry quorum check")
	proofFile := flag.String("proof", "", "unified destruction proof JSON")
	receiptsDir := flag.String("receipts", "", "directory of operator destruction receipt JSON files")
	bundleFile := flag.String("bundle", "", "optional bundle JSON with proof and receipts")
	challengeHex := flag.String("challenge", "", "optional nonce challenge hex")
	flag.Parse()

	var proof destruction.Proof
	var receipts []destruction.Receipt
	var err error

	if *bundleFile != "" {
		proof, receipts, err = loadBundle(*bundleFile)
	} else {
		if *proofFile == "" {
			log.Fatal("proof file or bundle file is required")
		}
		proof, err = loadProof(*proofFile)
		if err != nil {
			log.Fatal(err)
		}
		receipts, err = loadReceiptsDir(*receiptsDir)
		if err != nil {
			log.Fatal(err)
		}
		receipts = filterReceiptsForProof(proof, receipts)
	}
	if err != nil {
		log.Fatal(err)
	}

	result := pkgverify.VerifyDeletion(proof, receipts, *registryURL, *tenantID, *challengeHex, nil)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
	if !result.OverallOK {
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "VERIFIED — destruction %s is authentic.\n", result.DestructionID)
}

func loadBundle(path string) (destruction.Proof, []destruction.Receipt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return destruction.Proof{}, nil, err
	}
	var bundle struct {
		Proof    destruction.Proof     `json:"proof"`
		Receipts []destruction.Receipt `json:"receipts"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		return destruction.Proof{}, nil, err
	}
	return bundle.Proof, bundle.Receipts, nil
}

func loadProof(path string) (destruction.Proof, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return destruction.Proof{}, err
	}
	var proof destruction.Proof
	if err := json.Unmarshal(data, &proof); err != nil {
		return destruction.Proof{}, err
	}
	return proof, nil
}

func loadReceiptsDir(dir string) ([]destruction.Receipt, error) {
	if dir == "" {
		return nil, fmt.Errorf("receipts directory is required when bundle is not used")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var receipts []destruction.Receipt
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var rcpt destruction.Receipt
		if err := json.Unmarshal(data, &rcpt); err != nil {
			return nil, err
		}
		receipts = append(receipts, rcpt)
	}
	if len(receipts) == 0 {
		return nil, fmt.Errorf("no receipt JSON files found in %s", dir)
	}
	return receipts, nil
}

func filterReceiptsForProof(proof destruction.Proof, receipts []destruction.Receipt) []destruction.Receipt {
	if proof.Package == nil {
		return receipts
	}
	wantID, _ := proof.Package["destruction_id"].(string)
	if wantID == "" {
		return receipts
	}
	filtered := make([]destruction.Receipt, 0, len(receipts))
	for _, rcpt := range receipts {
		if rcpt.DestructionID() == wantID {
			filtered = append(filtered, rcpt)
		}
	}
	if len(filtered) == 0 {
		return receipts
	}
	return filtered
}
