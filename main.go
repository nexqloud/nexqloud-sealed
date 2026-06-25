package main

import (
	"log"

	"nexqloud-sealed/internal/enclave"
)

func main() {
	nonce := []byte("enclave-shim-nonce-12345678")

	_, pub, err := enclave.Key()
	if err != nil {
		log.Fatalf("failed to generate keypair: %v", err)
	}

	if err := enclave.WarmCertificateCache(pub); err != nil {
		log.Fatalf("failed to warm certificate cache: %v", err)
	}

	_, err = enclave.RequestReport(pub, nonce)
	if err != nil {
		log.Fatalf("failed to request attestation report: %v", err)
	}

	log.Println("Success: Keypair generated and bound to hardware report.")
}
