// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package trustlist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeRootCert builds a self-signed CA root and returns the cert, its private
// key (so callers can issue leaves), and its PEM.
func makeRootCert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Country: []string{"SE"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return cert, priv, pemStr
}

// makeLeafCert issues a signing leaf certificate signed by the given root.
func makeLeafCert(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, cn string, notAfter time.Time) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf keygen: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: cn, Country: []string{"SE"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, root, &priv.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// selfSignedLeaf builds a self-signed cert pretending to be a leaf (the
// forgery the attacker controls).
func selfSignedLeaf(t *testing.T, cn string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create forged leaf: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func writeTrustList(t *testing.T, dir string, f File) string {
	t.Helper()
	body, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, "trustlist.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func writeRaw(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "trustlist.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestLoad_EmptyPathIsNoOp(t *testing.T) {
	v, err := Load("")
	if err != nil {
		t.Fatalf("empty path should not error, got %v", err)
	}
	if v != nil {
		t.Errorf("empty path should return nil validator")
	}
}

func TestLoad_MissingFileErrors(t *testing.T) {
	if _, err := Load("/nonexistent/path/trustlist.json"); err == nil {
		t.Fatal("missing file should error")
	}
}

func TestLoad_MalformedJSONErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeRaw(t, dir, `{not valid json}`)
	if _, err := Load(path); err == nil {
		t.Fatal("malformed json should error")
	}
}

func TestLoad_MissingRootPEMErrors(t *testing.T) {
	root, _, _ := makeRootCert(t, "Idura QES Root CA 2025")
	dir := t.TempDir()
	path := writeTrustList(t, dir, File{TrustedRoots: []TrustedRoot{
		{QTSP: "Idura", SubjectCN: "Idura QES Root CA 2025", SHA256Fingerprint: Fingerprint(root)}, // no root_pem
	}})
	if _, err := Load(path); err == nil {
		t.Fatal("missing root_pem should fail load (fail closed)")
	}
}

func TestLoad_FingerprintMismatchErrors(t *testing.T) {
	root, _, rootPEM := makeRootCert(t, "Real Root")
	_ = root
	dir := t.TempDir()
	path := writeTrustList(t, dir, File{TrustedRoots: []TrustedRoot{
		{QTSP: "X", SubjectCN: "Real Root", SHA256Fingerprint: "deadbeef", RootPEM: rootPEM},
	}})
	if _, err := Load(path); err == nil {
		t.Fatal("declared fingerprint != root_pem hash should fail load")
	}
}

func TestValidateChain_ValidLeafAccepts(t *testing.T) {
	root, rootKey, rootPEM := makeRootCert(t, "Idura QES Root CA 2025")
	leafPEM := makeLeafCert(t, root, rootKey, "Anna Andersson", time.Now().Add(24*time.Hour))

	dir := t.TempDir()
	path := writeTrustList(t, dir, File{Version: "test", TrustedRoots: []TrustedRoot{
		{QTSP: "Idura Sweden AB", Country: "SE", SubjectCN: "Idura QES Root CA 2025", SHA256Fingerprint: Fingerprint(root), RootPEM: rootPEM},
	}})
	v, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	matched, err := v.ValidateChain(leafPEM + rootPEM)
	if err != nil {
		t.Fatalf("valid leaf should pass: %v", err)
	}
	if matched == nil || matched.QTSP != "Idura Sweden AB" {
		t.Errorf("matched root metadata wrong: %+v", matched)
	}
}

// The exact attack the old code allowed: forge a self-signed leaf and append a
// genuine (public) allow-listed root. It must now be rejected.
func TestValidateChain_ForgedLeafGenuineRootRejected(t *testing.T) {
	root, _, rootPEM := makeRootCert(t, "Idura QES Root CA 2025")
	forged := selfSignedLeaf(t, "Mallory (forged)")

	dir := t.TempDir()
	path := writeTrustList(t, dir, File{TrustedRoots: []TrustedRoot{
		{QTSP: "Idura", SubjectCN: "Idura QES Root CA 2025", SHA256Fingerprint: Fingerprint(root), RootPEM: rootPEM},
	}})
	v, _ := Load(path)
	if _, err := v.ValidateChain(forged + rootPEM); err == nil {
		t.Fatal("forged leaf + genuine root MUST be rejected")
	}
}

func TestValidateChain_UntrustedRootRejects(t *testing.T) {
	trustedRoot, _, trustedPEM := makeRootCert(t, "Trusted Root")
	otherRoot, otherKey, _ := makeRootCert(t, "Sketchy CA")
	leafPEM := makeLeafCert(t, otherRoot, otherKey, "Leaf", time.Now().Add(24*time.Hour))

	dir := t.TempDir()
	path := writeTrustList(t, dir, File{TrustedRoots: []TrustedRoot{
		{QTSP: "Trusted", SubjectCN: "Trusted Root", SHA256Fingerprint: Fingerprint(trustedRoot), RootPEM: trustedPEM},
	}})
	v, _ := Load(path)
	_, err := v.ValidateChain(leafPEM)
	if err == nil {
		t.Fatal("leaf under an untrusted root should be rejected")
	}
	var rerr *ErrRootNotTrusted
	if !errors.As(err, &rerr) {
		t.Errorf("expected ErrRootNotTrusted, got %T: %v", err, err)
	}
}

func TestValidateChain_ExpiredLeafRejected(t *testing.T) {
	root, rootKey, rootPEM := makeRootCert(t, "Root")
	expired := makeLeafCert(t, root, rootKey, "Old Leaf", time.Now().Add(-time.Minute))

	dir := t.TempDir()
	path := writeTrustList(t, dir, File{TrustedRoots: []TrustedRoot{
		{QTSP: "Q", SubjectCN: "Root", SHA256Fingerprint: Fingerprint(root), RootPEM: rootPEM},
	}})
	v, _ := Load(path)
	_, err := v.ValidateChain(expired + rootPEM)
	if err == nil {
		t.Fatal("expired leaf should be rejected")
	}
	var nverr *ErrChainNotVerified
	if !errors.As(err, &nverr) {
		t.Errorf("expected ErrChainNotVerified for expired leaf, got %T: %v", err, err)
	}
}

func TestValidateChain_EmptyChainErrors(t *testing.T) {
	root, _, rootPEM := makeRootCert(t, "Root")
	dir := t.TempDir()
	path := writeTrustList(t, dir, File{TrustedRoots: []TrustedRoot{
		{SubjectCN: "Root", SHA256Fingerprint: Fingerprint(root), RootPEM: rootPEM},
	}})
	v, _ := Load(path)
	if _, err := v.ValidateChain(""); !errors.Is(err, ErrChainEmpty) {
		t.Errorf("empty chain should return ErrChainEmpty, got %v", err)
	}
}

func TestValidateChain_NilValidatorIsNoOp(t *testing.T) {
	var v *Validator
	if matched, err := v.ValidateChain("anything"); matched != nil || err != nil {
		t.Errorf("nil validator should pass through, got matched=%v err=%v", matched, err)
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	cases := map[string]string{
		"AB:CD:EF":   "abcdef",
		"ab cd ef":   "abcdef",
		"  ABCDEF  ": "abcdef",
		"":           "",
	}
	for in, want := range cases {
		if got := normalizeFingerprint(in); got != want {
			t.Errorf("normalize(%q) = %q want %q", in, got, want)
		}
	}
}
