package tlog

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
)

func rekorServerURL() string {
	if url := os.Getenv("REKOR_SERVER"); url != "" {
		return url
	}
	return "https://rekor.sigstore.dev"
}

func AppendToLog(pkgBytes []byte, sigHex string, priv ed25519.PrivateKey) string {
	return appendToLog(pkgBytes, strings.TrimSpace(sigHex), priv)
}

func AppendToLogAsync(pkgBytes []byte, sigHex string, priv ed25519.PrivateKey) {
	pkgCopy := append([]byte(nil), pkgBytes...)
	sigCopy := strings.TrimSpace(sigHex)
	privCopy := append(ed25519.PrivateKey(nil), priv...)

	go func() {
		if idx := appendToLog(pkgCopy, sigCopy, privCopy); idx != "" {
			log.Printf("rekor: async upload complete log_index=%s", idx)
		}
	}()
}

func appendToLog(pkgBytes []byte, sigHex string, priv ed25519.PrivateKey) string {
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		log.Printf("rekor: decode signature: %v", err)
		return ""
	}

	certPEM, err := selfSignedCertificatePEM(priv)
	if err != nil {
		log.Printf("rekor: generate certificate: %v", err)
		return ""
	}

	sigContent := strfmt.Base64(sigBytes)
	pubContent := strfmt.Base64(certPEM)

	entry := models.Rekord{
		APIVersion: conv.Pointer("0.0.1"),
		Spec: models.RekordV001Schema{
			Data: &models.RekordV001SchemaData{
				Content: strfmt.Base64(pkgBytes),
			},
			Signature: &models.RekordV001SchemaSignature{
				Content: &sigContent,
				Format:  conv.Pointer(models.RekordV001SchemaSignatureFormatX509),
				PublicKey: &models.RekordV001SchemaSignaturePublicKey{
					Content: &pubContent,
				},
			},
		},
	}

	rc, err := rekorclient.GetRekorClient(rekorServerURL())
	if err != nil {
		log.Printf("rekor: client: %v", err)
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	params := entries.NewCreateLogEntryParams().
		WithContext(ctx).
		WithProposedEntry(&entry)

	resp, err := rc.Entries.CreateLogEntry(params)
	if err != nil {
		log.Printf("rekor: create entry: %v", err)
		return ""
	}

	for _, logEntry := range resp.GetPayload() {
		if logEntry.LogIndex != nil {
			return strconv.FormatInt(*logEntry.LogIndex, 10)
		}
	}

	log.Printf("rekor: response missing log index")
	return ""
}

func selfSignedCertificatePEM(priv ed25519.PrivateKey) ([]byte, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, x509.ErrUnsupportedAlgorithm
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Sealed Enclave"},
			CommonName:   "sealed-enclave",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}), nil
}
