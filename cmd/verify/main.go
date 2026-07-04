package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/encoding/protojson"

	iv "nexqloud-sealed/internal/verify"
	pkgverify "nexqloud-sealed/pkg/verify"
)

func main() {
	challenge := flag.String("challenge", "", "expected freshness nonce (hex)")
	askPath := flag.String("ask", "", "path to AMD ASK root certificate (DER)")
	arkPath := flag.String("ark", "", "path to AMD ARK root certificate (DER)")
	productLine := flag.String("product", "", "AMD product line for custom roots (e.g. Milan, Genoa)")
	noColor := flag.Bool("no-color", false, "disable ANSI colors")
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

	catalog, err := pkgverify.LoadHardwareRootsCatalog()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load AMD roots: %v\n", err)
		os.Exit(1)
	}

	product := *productLine
	if *askPath != "" || *arkPath != "" {
		if *askPath == "" || *arkPath == "" {
			fmt.Fprintf(os.Stderr, "both --ask and --ark are required when providing custom AMD roots\n")
			os.Exit(1)
		}
		ask, err := os.ReadFile(*askPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read ASK: %v\n", err)
			os.Exit(1)
		}
		ark, err := os.ReadFile(*arkPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read ARK: %v\n", err)
			os.Exit(1)
		}
		if product == "" {
			product, err = inferProductLine(data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "infer product line: %v (use --product)\n", err)
				os.Exit(1)
			}
		}
		catalog = pkgverify.ApplyCustomHardwareRoots(catalog, product, ask, ark)
	}

	result := pkgverify.VerifyReceiptJSON(data, *challenge, catalog)
	if result.Error != "" {
		fmt.Fprintf(os.Stderr, "%s\n", result.Error)
		os.Exit(1)
	}

	printResults(os.Stdout, result, *challenge, useColor(*noColor))
	if !result.OverallOK {
		os.Exit(1)
	}
}

func inferProductLine(receiptJSON []byte) (string, error) {
	var wrapper struct {
		Attestation json.RawMessage `json:"attestation"`
	}
	if err := json.Unmarshal(receiptJSON, &wrapper); err != nil {
		return "", err
	}
	att := &sevsnp.Attestation{}
	if len(wrapper.Attestation) > 0 && string(wrapper.Attestation) != "{}" {
		if err := protojson.Unmarshal(wrapper.Attestation, att); err != nil {
			return "", err
		}
	}
	return iv.ProductLineFromReport(att)
}
