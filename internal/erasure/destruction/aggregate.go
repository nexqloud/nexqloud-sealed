package destruction

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"

	"nexqloud-sealed/internal/receipt"
	"nexqloud-sealed/internal/tlog"
)

type Proof struct {
	Package    map[string]any `json:"package"`
	Signature  string         `json:"signature"`
	Pubkey     string         `json:"pubkey"`
	LogIndex   string         `json:"log_index"`
	tenantHash string
	quorum     []string
	root       []byte
	at         string
	destructionID string
}

func (p Proof) PackageMap() map[string]any {
	if p.Package != nil {
		return p.Package
	}
	rootHex := ""
	if len(p.root) > 0 {
		rootHex = "sha256:" + hex.EncodeToString(p.root)
	}
	return map[string]any{
		"schema":          ProofSchema,
		"destruction_id":  p.destructionID,
		"tenant_id_hash":  p.tenantHash,
		"quorum":          p.quorum,
		"merkle_root":     rootHex,
		"at":              p.at,
	}
}

func Aggregate(want []string, got []Receipt, destructionID string, substrateSK ed25519.PrivateKey) (Proof, error) {
	if !sameSet(want, operatorsOf(got)) {
		return Proof{}, fmt.Errorf("incomplete quorum: data would remain recoverable")
	}

	tenantHash := got[0].TenantHash()
	for _, r := range got[1:] {
		if r.TenantHash() != tenantHash {
			return Proof{}, fmt.Errorf("tenant_id_hash mismatch across receipts")
		}
	}

	leaves := canonicalLeaves(got)
	root := merkleRoot(leaves)
	at := time.Now().UTC().Format(time.RFC3339)

	proof := Proof{
		tenantHash:    tenantHash,
		quorum:        append([]string(nil), want...),
		root:          root,
		at:            at,
		destructionID: destructionID,
	}
	pkg := proof.PackageMap()
	canonical, err := receipt.Canonicalize(pkg)
	if err != nil {
		return Proof{}, fmt.Errorf("canonicalize proof: %w", err)
	}

	sig := ed25519.Sign(substrateSK, canonical)
	pub := substrateSK.Public().(ed25519.PublicKey)
	logIndex := tlog.AppendToLog(canonical, hex.EncodeToString(sig), substrateSK)

	proof.Package = pkg
	proof.Signature = hex.EncodeToString(sig)
	proof.Pubkey = hex.EncodeToString(pub)
	proof.LogIndex = logIndex
	return proof, nil
}

func VerifyProofMerkle(p Proof, want []string, got []Receipt) error {
	if err := VerifyProof(p); err != nil {
		return err
	}
	if !sameSet(want, operatorsOf(got)) {
		return fmt.Errorf("quorum mismatch")
	}
	leaves := canonicalLeaves(got)
	root := merkleRoot(leaves)
	expected, _ := p.Package["merkle_root"].(string)
	actual := "sha256:" + hex.EncodeToString(root)
	if expected != actual {
		return fmt.Errorf("merkle root mismatch: got %s want %s", expected, actual)
	}
	return nil
}

func VerifyProof(p Proof) error {
	if p.Package == nil {
		return fmt.Errorf("missing package")
	}
	schema, _ := p.Package["schema"].(string)
	if schema != ProofSchema {
		return fmt.Errorf("invalid schema %q", schema)
	}

	pub, err := hex.DecodeString(p.Pubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid pubkey")
	}
	sig, err := hex.DecodeString(p.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}

	canonical, err := receipt.Canonicalize(p.Package)
	if err != nil {
		return fmt.Errorf("canonicalize package: %w", err)
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
