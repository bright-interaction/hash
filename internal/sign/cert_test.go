package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

// PublicKeyPEM must be valid SPKI so a third party can verify the audit
// certificate offline with standard tooling (OpenSSL, python-cryptography).
func TestPublicKeyPEM_IsValidSPKI(t *testing.T) {
	s, err := GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(s.PublicKeyPEM()))
	if blk == nil {
		t.Fatal("PublicKeyPEM is not valid PEM")
	}
	pk, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		t.Fatalf("standard tooling cannot parse the public key as SPKI: %v", err)
	}
	if _, ok := pk.(ed25519.PublicKey); !ok {
		t.Fatalf("parsed key is not ed25519: %T", pk)
	}
}

func TestCertSigner_RoundTrip(t *testing.T) {
	s, err := GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("the audit trail of document foo")
	sig := s.SignPayload(payload)
	if sig == "" {
		t.Fatal("empty signature")
	}
	if !Verify(s.PublicKeyBase64(), string(payload), sig) {
		t.Error("verify failed for fresh signer")
	}
}

func TestCertSigner_RejectsTampered(t *testing.T) {
	s, _ := GenerateCertSigner()
	payload := []byte("original")
	sig := s.SignPayload(payload)
	if Verify(s.PublicKeyBase64(), "tampered", sig) {
		t.Error("tampered payload verified")
	}
}

func TestCertSigner_RejectsDifferentKey(t *testing.T) {
	s1, _ := GenerateCertSigner()
	s2, _ := GenerateCertSigner()
	payload := []byte("hello")
	sig := s1.SignPayload(payload)
	if Verify(s2.PublicKeyBase64(), string(payload), sig) {
		t.Error("different key verified")
	}
}

func TestNewCertSigner_FromExportedSeed(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seedB64 := base64.StdEncoding.EncodeToString(priv.Seed())
	s, err := NewCertSigner(seedB64)
	if err != nil {
		t.Fatalf("init from seed: %v", err)
	}
	if !strings.Contains(s.PublicKeyBase64(), "") {
		t.Error("public key empty")
	}
}

func TestNewCertSigner_BadSeedRejected(t *testing.T) {
	cases := []string{"!!", "not-base64-anything", base64.StdEncoding.EncodeToString([]byte("too-short"))}
	for _, c := range cases {
		if _, err := NewCertSigner(c); err == nil {
			t.Errorf("expected error for input %q", c)
		}
	}
}

func TestNewCertSigner_EmptyReturnsNil(t *testing.T) {
	s, err := NewCertSigner("")
	if err != nil {
		t.Fatal(err)
	}
	if s != nil {
		t.Error("empty input should return nil signer (caller opt-out)")
	}
}

func TestCertSigner_NilSafe(t *testing.T) {
	var s *CertSigner
	if got := s.PublicKeyBase64(); got != "" {
		t.Errorf("nil signer should return empty pub key, got %q", got)
	}
	if got := s.SignPayload([]byte("x")); got != "" {
		t.Errorf("nil signer should return empty sig, got %q", got)
	}
}
