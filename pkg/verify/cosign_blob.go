package verify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// CosignSimpleBundle is the JSON shape produced by
// `cosign sign-blob --bundle` (legacy simple signing format).
type CosignSimpleBundle struct {
	Base64Signature string          `json:"base64Signature"`
	Cert            string          `json:"cert"`
	RekorBundle     json.RawMessage `json:"rekorBundle"`
}

type rekorBundle struct {
	SignedEntryTimestamp string          `json:"SignedEntryTimestamp"`
	Payload              json.RawMessage `json:"Payload"`
}

type rekorPayload struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogIndex       int64  `json:"logIndex"`
	LogID          string `json:"logID"`
}

type hashedRekordBody struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
	} `json:"spec"`
}

// VerifyCosignBlobBundle verifies a cosign sign-blob bundle offline:
// payload signature, Fulcio chain at Rekor integrated time, Rekor SET, and
// GitHub Actions workflow identity. Does not contact the network.
func VerifyCosignBlobBundle(payload []byte, bundleJSON []byte) error {
	var bundle CosignSimpleBundle
	if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}
	if bundle.Base64Signature == "" || bundle.Cert == "" || len(bundle.RekorBundle) == 0 {
		return fmt.Errorf("bundle missing signature, cert, or rekorBundle")
	}

	certDEROrPEM, err := decodeBundleCert(bundle.Cert)
	if err != nil {
		return err
	}
	cert, err := parseCertificate(certDEROrPEM)
	if err != nil {
		return fmt.Errorf("parse signing cert: %w", err)
	}

	var rb rekorBundle
	if err := json.Unmarshal(bundle.RekorBundle, &rb); err != nil {
		return fmt.Errorf("parse rekorBundle: %w", err)
	}
	integratedTime, err := verifyRekorSET(rb)
	if err != nil {
		return fmt.Errorf("rekor SET: %w", err)
	}

	var payloadMeta rekorPayload
	if err := json.Unmarshal(rb.Payload, &payloadMeta); err != nil {
		return fmt.Errorf("parse rekor payload: %w", err)
	}
	if err := verifyHashedRekordMatchesPayload(payloadMeta.Body, payload); err != nil {
		return err
	}

	if err := verifyFulcioChainAt(cert, integratedTime); err != nil {
		return fmt.Errorf("fulcio chain: %w", err)
	}
	if err := verifyGitHubActionsIdentity(cert); err != nil {
		return fmt.Errorf("identity: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(bundle.Base64Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("signing cert is not ECDSA")
	}
	sum := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return fmt.Errorf("blob signature mismatch")
	}
	return nil
}

func decodeBundleCert(certField string) ([]byte, error) {
	if strings.Contains(certField, "BEGIN CERTIFICATE") {
		return []byte(certField), nil
	}
	raw, err := base64.StdEncoding.DecodeString(certField)
	if err != nil {
		return nil, fmt.Errorf("decode cert: %w", err)
	}
	return raw, nil
}

func parseCertificate(pemOrDER []byte) (*x509.Certificate, error) {
	if block, _ := pem.Decode(pemOrDER); block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	return x509.ParseCertificate(pemOrDER)
}

func verifyRekorSET(rb rekorBundle) (time.Time, error) {
	if rb.SignedEntryTimestamp == "" || len(rb.Payload) == 0 {
		return time.Time{}, fmt.Errorf("missing SET or payload")
	}
	var payloadMap map[string]any
	if err := json.Unmarshal(rb.Payload, &payloadMap); err != nil {
		return time.Time{}, err
	}
	canonical, err := json.Marshal(payloadMap)
	if err != nil {
		return time.Time{}, err
	}

	sig, err := base64.StdEncoding.DecodeString(rb.SignedEntryTimestamp)
	if err != nil {
		return time.Time{}, fmt.Errorf("decode SET: %w", err)
	}
	pub, err := parseRekorPublicKey()
	if err != nil {
		return time.Time{}, err
	}
	sum := sha256.Sum256(canonical)
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return time.Time{}, fmt.Errorf("SET signature invalid")
	}

	var meta rekorPayload
	if err := json.Unmarshal(rb.Payload, &meta); err != nil {
		return time.Time{}, err
	}
	wantLogID := strings.TrimSpace(rekorLogIDHex)
	if meta.LogID != "" && !strings.EqualFold(meta.LogID, wantLogID) {
		return time.Time{}, fmt.Errorf("rekor logID mismatch")
	}
	if meta.IntegratedTime <= 0 {
		return time.Time{}, fmt.Errorf("missing integratedTime")
	}
	return time.Unix(meta.IntegratedTime, 0).UTC(), nil
}

func parseRekorPublicKey() (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(rekorPubKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("decode rekor pubkey pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("rekor key is not ECDSA")
	}
	return ecPub, nil
}

func verifyHashedRekordMatchesPayload(bodyB64 string, payload []byte) error {
	raw, err := base64.StdEncoding.DecodeString(bodyB64)
	if err != nil {
		return fmt.Errorf("decode rekor body: %w", err)
	}
	var body hashedRekordBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return fmt.Errorf("parse hashedrekord: %w", err)
	}
	if body.Kind != "hashedrekord" {
		return fmt.Errorf("unexpected rekor kind %q", body.Kind)
	}
	if !strings.EqualFold(body.Spec.Data.Hash.Algorithm, "sha256") {
		return fmt.Errorf("unexpected hash algorithm %q", body.Spec.Data.Hash.Algorithm)
	}
	sum := sha256.Sum256(payload)
	got := strings.ToLower(body.Spec.Data.Hash.Value)
	want := hex.EncodeToString(sum[:])
	if got != want {
		return fmt.Errorf("rekor hashedrekord hash mismatch")
	}
	return nil
}

func verifyFulcioChainAt(leaf *x509.Certificate, at time.Time) error {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(fulcioRootPEM) {
		return fmt.Errorf("load fulcio root")
	}
	if !intermediates.AppendCertsFromPEM(fulcioIntermediatePEM) {
		return fmt.Errorf("load fulcio intermediate")
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return err
	}
	return nil
}

var oidIssuer = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
var oidRepo = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5}

func verifyGitHubActionsIdentity(cert *x509.Certificate) error {
	var sanURI string
	for _, u := range cert.URIs {
		sanURI = u.String()
		break
	}
	if sanURI == "" || !strings.HasPrefix(sanURI, DefaultWorkflowSANPrefix) {
		return fmt.Errorf("SAN URI %q not an allowed sealed-initrd workflow identity", sanURI)
	}
	ref := strings.TrimPrefix(sanURI, DefaultWorkflowSANPrefix)
	if !allowedWorkflowRef(ref) {
		return fmt.Errorf("workflow ref %q not allowed", ref)
	}

	issuer, err := fulcioExtString(cert, oidIssuer)
	if err != nil {
		return err
	}
	if issuer != DefaultOIDCIssuer {
		return fmt.Errorf("OIDC issuer %q not allowed", issuer)
	}
	repo, err := fulcioExtString(cert, oidRepo)
	if err != nil {
		return err
	}
	if repo != DefaultRepo {
		return fmt.Errorf("repo %q not allowed", repo)
	}
	return nil
}

func allowedWorkflowRef(ref string) bool {
	switch {
	case ref == "refs/heads/stage", ref == "refs/heads/main":
		return true
	case strings.HasPrefix(ref, "refs/tags/v"):
		return true
	default:
		return false
	}
}

func fulcioExtString(cert *x509.Certificate, oid asn1.ObjectIdentifier) (string, error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oid) {
			continue
		}
		v := strings.TrimSpace(string(ext.Value))
		if v != "" {
			return v, nil
		}
		var s string
		if _, err := asn1.Unmarshal(ext.Value, &s); err == nil && s != "" {
			return s, nil
		}
	}
	return "", fmt.Errorf("missing fulcio extension %s", oid.String())
}

// MeasurementFromPayload returns the hex measurement from signed payload bytes.
func MeasurementFromPayload(payload []byte) string {
	return strings.ToLower(strings.TrimSpace(string(payload)))
}
