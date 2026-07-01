package enclave

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"

	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/proto/sevsnp"
)

func Key() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, pub, err
}

func RequestReport(pub ed25519.PublicKey, nonce []byte) (*sevsnp.Attestation, error) {
	if err := WarmCertificateCache(pub); err != nil {
		return nil, err
	}

	att, err := requestHardwareReport(pub, nonce)
	if err != nil {
		return nil, err
	}
	if err := AttachCertificateChain(att); err != nil {
		return att, err
	}
	return att, nil
}

func requestHardwareReport(pub ed25519.PublicKey, nonce []byte) (*sevsnp.Attestation, error) {
	hash := sha512.Sum512(append(append([]byte{}, pub...), nonce...))
	var reportData [64]byte
	copy(reportData[:], hash[:])

	qp, err := client.GetQuoteProvider()
	if err == nil {
		return client.GetQuoteProto(qp, reportData)
	}

	return azureRequestReport(reportData)
}

func KeyHash(pub ed25519.PublicKey, nonce []byte) [64]byte {
	return sha512.Sum512(append(append([]byte{}, pub...), nonce...))
}
