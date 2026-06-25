package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/encoding/protojson"

	"nexqloud-sealed/internal/receipt"
	"nexqloud-sealed/internal/verify"
)

func main() {
	askPath := flag.String("ask", "", "path to AMD ASK root certificate (DER)")
	arkPath := flag.String("ark", "", "path to AMD ARK root certificate (DER)")
	productLine := flag.String("product", "", "AMD product line for custom roots (e.g. Milan, Genoa)")
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <receipt.json>\n", os.Args[0])
		os.Exit(1)
	}

	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read receipt: %v\n", err)
		os.Exit(1)
	}

	var wrapper receipt.SealedReceipt
	if err := json.Unmarshal(data, &wrapper); err != nil {
		fmt.Fprintf(os.Stderr, "parse receipt: %v\n", err)
		os.Exit(1)
	}

	pub, err := hex.DecodeString(wrapper.Pubkey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode pubkey: %v\n", err)
		os.Exit(1)
	}
	if len(pub) != ed25519.PublicKeySize {
		fmt.Fprintf(os.Stderr, "invalid pubkey length: %d\n", len(pub))
		os.Exit(1)
	}

	nonce, err := hex.DecodeString(wrapper.Package.Nonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode nonce: %v\n", err)
		os.Exit(1)
	}

	att := &sevsnp.Attestation{}
	if len(wrapper.Attestation) > 0 && string(wrapper.Attestation) != "{}" {
		if err := protojson.Unmarshal(wrapper.Attestation, att); err != nil {
			fmt.Fprintf(os.Stderr, "parse attestation: %v\n", err)
			os.Exit(1)
		}
	}

	roots, err := loadHardwareRoots(*askPath, *arkPath, *productLine)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load AMD roots: %v\n", err)
		os.Exit(1)
	}

	rc := verify.AttestationReceipt{
		Attestation: att,
		CertChain:   wrapper.CertChain,
	}
	pins := verify.Pins{
		Nonce:              nonce,
		EnclaveMeasurement: wrapper.Package.EnclaveMeasurement,
		ModelCommitment:    wrapper.Package.ModelCommitment,
	}

	result := verify.Verify(rc, ed25519.PublicKey(pub), pins, wrapper.RuntimeClaimsJSON, roots)
	if !result.OK {
		fmt.Fprintf(os.Stderr, "%s\n", result.Reason)
		os.Exit(1)
	}

	fmt.Printf("VERIFIED — receipt %s is authentic.\n", wrapper.Package.ReceiptID)
}

func loadHardwareRoots(askPath, arkPath, productLine string) (verify.HardwareRoots, error) {
	if askPath == "" && arkPath == "" {
		return verify.HardwareRoots{}, nil
	}
	if askPath == "" || arkPath == "" {
		return verify.HardwareRoots{}, fmt.Errorf("both --ask and --ark are required when providing custom AMD roots")
	}

	ask, err := os.ReadFile(askPath)
	if err != nil {
		return verify.HardwareRoots{}, err
	}
	ark, err := os.ReadFile(arkPath)
	if err != nil {
		return verify.HardwareRoots{}, err
	}

	return verify.HardwareRoots{
		ProductLine: productLine,
		ASK:         ask,
		ARK:         ark,
	}, nil
}
