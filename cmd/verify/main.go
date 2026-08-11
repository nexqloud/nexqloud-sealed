package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/encoding/protojson"

	iv "nexqloud-sealed/internal/verify"
	pkgverify "nexqloud-sealed/pkg/verify"
)

func main() {
	setupSlog()

	challenge := flag.String("challenge", "", "expected freshness nonce (hex)")
	askPath := flag.String("ask", "", "path to AMD ASK root certificate (DER)")
	arkPath := flag.String("ark", "", "path to AMD ARK root certificate (DER)")
	productLine := flag.String("product", "", "AMD product line for custom roots (e.g. Milan, Genoa)")
	noColor := flag.Bool("no-color", false, "disable ANSI colors")
	r2Base := flag.String("r2-base", pkgverify.DefaultR2PublicBase, "public R2 base URL for sealed-initrd releases")
	initrdEnv := flag.String("initrd-env", "staging,production", "comma-separated R2 envs to load allowlists from")
	noFetchMeas := flag.Bool("no-fetch-measurements", false, "skip fetching Sigstore proofs / allowlists from R2")
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

	opts := pkgverify.VerifyOpts{
		ChallengeHex: *challenge,
		RootsCatalog: catalog,
	}

	if !*noFetchMeas {
		envs := splitCSV(*initrdEnv)
		meas := extractLaunchMeasurement(data)
		if meas != "" {
			proof, err := pkgverify.FetchProofForMeasurement(*r2Base, envs, meas)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: fetch Sigstore proof: %v (falling back to R2 allowlist hex)\n", err)
				if hexes, herr := pkgverify.FetchAllowlistMeasurements(*r2Base, envs); herr == nil && len(hexes) > 0 {
					opts.Measurements = hexes
					fmt.Fprintf(os.Stderr, "loaded %d allowlist measurement(s) from R2\n", len(hexes))
				}
			} else {
				opts.MeasurementProofs = []pkgverify.MeasurementProof{proof}
				fmt.Fprintf(os.Stderr, "loaded Sigstore proof for measurement %s… (git %s, env %s)\n",
					meas[:16], truncate(proof.GitSHA, 12), proof.Environment)
			}
		} else if hexes, err := pkgverify.FetchAllowlistMeasurements(*r2Base, envs); err != nil {
			fmt.Fprintf(os.Stderr, "warning: fetch allowlist: %v\n", err)
		} else if len(hexes) > 0 {
			opts.Measurements = hexes
			fmt.Fprintf(os.Stderr, "loaded %d allowlist measurement(s) from R2\n", len(hexes))
		}

		if models, err := pkgverify.FetchAllowlistModelCommitments(*r2Base, envs); err != nil {
			fmt.Fprintf(os.Stderr, "warning: fetch model allowlist: %v\n", err)
		} else if len(models) > 0 {
			opts.Models = models
			fmt.Fprintf(os.Stderr, "loaded %d model commitment(s) from R2\n", len(models))
		}
		if issuers, err := pkgverify.FetchAllowlistModelAttestIssuers(*r2Base, envs); err != nil {
			fmt.Fprintf(os.Stderr, "warning: fetch model-attest issuer allowlist: %v\n", err)
		} else if len(issuers) > 0 {
			opts.ModelAttestIssuers = issuers
			fmt.Fprintf(os.Stderr, "loaded %d model-attest issuer(s) from R2\n", len(issuers))
		}

		if hashes, err := pkgverify.FetchAllowlistGPUPolicyHashes(*r2Base, envs); err != nil {
			fmt.Fprintf(os.Stderr, "warning: fetch gpu policy allowlist: %v\n", err)
		} else if len(hashes) > 0 {
			opts.GPUPolicyHashes = hashes
			fmt.Fprintf(os.Stderr, "loaded %d gpu policy hash(es) from R2\n", len(hashes))
		}
		if issuers, err := pkgverify.FetchAllowlistWipeIssuers(*r2Base, envs); err != nil {
			fmt.Fprintf(os.Stderr, "warning: fetch wipe issuer allowlist: %v\n", err)
		} else if len(issuers) > 0 {
			opts.WipeIssuers = issuers
			fmt.Fprintf(os.Stderr, "loaded %d wipe issuer(s) from R2\n", len(issuers))
		}
		if workers, err := pkgverify.FetchAllowlistWipeWorkers(*r2Base, envs); err != nil {
			fmt.Fprintf(os.Stderr, "warning: fetch wipe worker allowlist: %v\n", err)
		} else if len(workers) > 0 {
			opts.WipeWorkers = workers
			fmt.Fprintf(os.Stderr, "loaded %d wipe worker commitment(s) from R2\n", len(workers))
		}
	}

	result := pkgverify.VerifyReceiptJSONOpts(data, opts)
	if result.Error != "" {
		fmt.Fprintf(os.Stderr, "%s\n", result.Error)
		os.Exit(1)
	}

	printResults(os.Stdout, result, *challenge, useColor(*noColor))
	if !result.OverallOK {
		os.Exit(1)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func extractLaunchMeasurement(receiptJSON []byte) string {
	var wrapper struct {
		Package     map[string]any  `json:"package"`
		Attestation json.RawMessage `json:"attestation"`
	}
	if err := json.Unmarshal(receiptJSON, &wrapper); err != nil {
		return ""
	}
	if wrapper.Package != nil {
		if m, ok := wrapper.Package["enclave_measurement"].(string); ok {
			m = strings.ToLower(strings.TrimSpace(m))
			if len(m) == 96 {
				return m
			}
		}
	}
	att := &sevsnp.Attestation{}
	if len(wrapper.Attestation) > 0 && string(wrapper.Attestation) != "{}" {
		if err := protojson.Unmarshal(wrapper.Attestation, att); err != nil {
			return ""
		}
	}
	if att.Report != nil && len(att.Report.Measurement) > 0 {
		return fmt.Sprintf("%x", att.Report.Measurement)
	}
	return ""
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func setupSlog() {
	level := slog.LevelInfo
	switch strings.ToLower(strings.TrimSpace(os.Getenv("NEXQLOUD_LOG_LEVEL"))) {
	case "debug", "dbg":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error", "err":
		level = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
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
