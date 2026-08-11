package main

import (
	"fmt"
	"io"
	"os"

	"nexqloud-sealed/pkg/verify"
)

const (
	ansiGreen  = "\033[32m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiBold   = "\033[1m"
	ansiReset  = "\033[0m"
)

func printResults(w io.Writer, result verify.ReceiptResult, challengeHex string, color bool) {
	for i, check := range result.Checks {
		line := formatCheckLine(i+1, check, challengeHex, color)
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)

	id := result.ReceiptID
	if id == "" {
		id = result.OperatorID
	}
	kind := "receipt"
	if result.Schema == "sealed-derivation/1" {
		kind = "derivation"
	}

	if result.OverallOK {
		fmt.Fprintf(w, "%sVERIFIED — %s %s is authentic.%s\n", bold(color), kind, id, reset(color))
	} else {
		fmt.Fprintf(w, "%sFAILED — %s %s did not pass verification.%s\n", fail(color), kind, id, reset(color))
	}
}

func formatCheckLine(n int, check verify.Check, challengeHex string, color bool) string {
	mark, markColor := checkMark(check, challengeHex, color)
	label := check.Label
	if label == "" {
		label = check.ID
	}

	detail := checkDetail(check, challengeHex)
	hash := ""
	if check.Hash != "" {
		hash = fmt.Sprintf(" (%s)", check.Hash)
	}

	return fmt.Sprintf("%d %s%s%s %s — %s",
		n,
		markColor,
		mark,
		reset(color),
		label+hash,
		detail,
	)
}

func checkMark(check verify.Check, challengeHex string, color bool) (string, string) {
	if check.ID == "freshness" && challengeHex == "" {
		return "○", skip(color)
	}
	if check.OK {
		return "✓", pass(color)
	}
	return "✗", fail(color)
}

func checkDetail(check verify.Check, challengeHex string) string {
	if check.ID == "freshness" && challengeHex == "" {
		return "Nonce present, but no challenge supplied to verify freshness"
	}
	if check.ID == "hardware_genuine" && check.ChainValidated {
		return "Attestation came from real AMD SEV-SNP hardware with a valid AMD certificate chain"
	}
	if check.Detail != "" {
		return check.Detail
	}
	return check.ID
}

func useColor(noColor bool) bool {
	if noColor {
		return false
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func pass(color bool) string {
	if !color {
		return ""
	}
	return ansiGreen
}

func fail(color bool) string {
	if !color {
		return ""
	}
	return ansiRed
}

func skip(color bool) string {
	if !color {
		return ""
	}
	return ansiYellow
}

func bold(color bool) string {
	if !color {
		return ""
	}
	return ansiGreen + ansiBold
}

func reset(color bool) string {
	if !color {
		return ""
	}
	return ansiReset
}
