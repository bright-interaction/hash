package evidence

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestIsTerminal(t *testing.T) {
	for _, ok := range []string{"completed", "declined", "voided", "expired"} {
		if !isTerminal(ok) {
			t.Errorf("%s should be terminal", ok)
		}
	}
	for _, no := range []string{"draft", "sent", "in_progress", "", "unknown"} {
		if isTerminal(no) {
			t.Errorf("%s should not be terminal", no)
		}
	}
}

func TestNoopOTSAnchor(t *testing.T) {
	a := NoopOTSAnchor{}
	out, err := a.Stamp(context.Background(), make([]byte, 32))
	if err != nil {
		t.Fatalf("noop should never error, got %v", err)
	}
	if out != nil {
		t.Fatalf("noop should return nil bytes, got %d", len(out))
	}
}

func TestHTTPOTSAnchor_RejectsWrongDigestSize(t *testing.T) {
	a := NewHTTPOTSAnchor("")
	_, err := a.Stamp(context.Background(), make([]byte, 31))
	if err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("expected 32-byte error, got %v", err)
	}
}

func TestFirstCertFromPEM_ExtractsLeaf(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Mock Signer Anna Anka",
			Organization: []string{"Hash Test"},
		},
		Issuer: pkix.Name{
			CommonName: "Mock QTSP Root",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	leaf, err := firstCertFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if leaf == nil || leaf.Subject.CommonName != "Mock Signer Anna Anka" {
		t.Errorf("subject CN = %q, want %q", leaf.Subject.CommonName, "Mock Signer Anna Anka")
	}
}

func TestFirstCertFromPEM_EmptyReturnsNil(t *testing.T) {
	leaf, err := firstCertFromPEM([]byte(""))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if leaf != nil {
		t.Errorf("expected nil cert on empty input")
	}
}

func TestManifest_QTSPBlockSerializes(t *testing.T) {
	m := Manifest{
		SchemaVersion: 1,
		DocumentID:    "doc-1",
		QTSP: []QTSPBlock{{
			Provider:            "idura",
			SessionID:           "sess-1",
			RecipientID:         "rec-1",
			CertChainSHA256:     hex.EncodeToString(make([]byte, 32)),
			CertChainAttachment: "qes-cert-chain-1.pem",
			SubjectCN:           "Test Subject",
		}},
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, `"qtsp":[{`) {
		t.Errorf("qtsp block missing from manifest JSON: %s", s)
	}
	if !strings.Contains(s, `"subject_cn":"Test Subject"`) {
		t.Errorf("subject_cn missing")
	}
}

func TestManifest_OmitsQTSPWhenEmpty(t *testing.T) {
	m := Manifest{SchemaVersion: 1, DocumentID: "doc-1"}
	out, _ := json.Marshal(m)
	if strings.Contains(string(out), "qtsp") {
		t.Errorf("expected qtsp omitted when empty: %s", out)
	}
}

func TestManifestCanonicalShape(t *testing.T) {
	m := Manifest{
		SchemaVersion:    1,
		DocumentID:       "doc-1",
		DocumentName:     "Test",
		FinalPDFSHA256:   hex.EncodeToString(make([]byte, 32)),
		EventsSHA256:     hex.EncodeToString(make([]byte, 32)),
		VersionsSHA256:   hex.EncodeToString(make([]byte, 32)),
		PublicKeyPEMHash: hex.EncodeToString(make([]byte, 32)),
		Bundle:           BundleSummary{EventCount: 5, VersionCount: 3},
	}
	if m.SchemaVersion != 1 {
		t.Fatal("schema_version should be 1")
	}
	if len(m.FinalPDFSHA256) != 64 {
		t.Fatalf("sha256 hex should be 64 chars, got %d", len(m.FinalPDFSHA256))
	}
}
