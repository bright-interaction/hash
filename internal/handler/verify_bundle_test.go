package handler

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	pdfmodel "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	pdftypes "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"

	"github.com/brightinteraction/hash/internal/sign"
)

// buildTestBundle assembles a synthetic Hash evidence bundle: a blank
// A4 PDF carrying a manifest + payload + signature + public key +
// events/versions attachments, signed with a freshly-minted ed25519
// signer. The output bytes are what handleVerifyBundle would receive.
func buildTestBundle(t *testing.T, mutate func(map[string][]byte)) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	pem := "-----BEGIN PUBLIC KEY-----\n" + pubB64 + "\n-----END PUBLIC KEY-----\n"

	payload := []byte(`<div class="hash-cert-page"><h2>Audit Certificate</h2><p>Doc test</p></div>`)
	digest := sha256.Sum256(append([]byte("hash:audit-cert:v1:"), payload...))
	sigBytes := ed25519.Sign(priv, digest[:])
	signature := []byte(base64.StdEncoding.EncodeToString(sigBytes))

	events := []byte(`{"events":[],"count":0}`)
	versions := []byte(`{"versions":[],"count":0}`)

	hash := func(b []byte) string {
		s := sha256.Sum256(b)
		return hex.EncodeToString(s[:])
	}
	manifest := map[string]any{
		"schema_version":          1,
		"document_id":             "11111111-1111-1111-1111-111111111111",
		"document_name":           "Test Doc",
		"issuer":                  "Hash Test",
		"generated_at":            "2026-05-12T00:00:00Z",
		"events_sha256":           hash(events),
		"versions_sha256":         hash(versions),
		"public_key_pem_sha256":   hash([]byte(pem)),
		"cert_payload_sha256":     hash(payload),
		"cert_signature_sha256":   hash(signature),
		"signature_algorithm":     "ed25519",
		"signature_domain":        "hash:audit-cert:v1",
	}
	manifestJSON, _ := json.MarshalIndent(manifest, "", "  ")

	files := map[string][]byte{
		"manifest.json":            manifestJSON,
		"events.json":              events,
		"versions.json":            versions,
		"public-key.pem":           []byte(pem),
		"audit-cert-payload.txt":   payload,
		"audit-cert-signature.txt": signature,
	}
	if mutate != nil {
		mutate(files)
	}

	// Generate a minimal blank PDF as the visible body.
	conf := pdfmodel.NewDefaultConfiguration()
	ctx, err := pdfcpu.CreateContextWithXRefTable(conf, pdftypes.PaperSize["A4"])
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	blankPath := filepath.Join(tmp, "blank.pdf")
	bf, err := os.Create(blankPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pdfapi.WriteContext(ctx, bf); err != nil {
		t.Fatal(err)
	}
	bf.Close()

	// Write attachments to disk + bind them via AddAttachmentsFile.
	attachPaths := make([]string, 0, len(files))
	for name, data := range files {
		p := filepath.Join(tmp, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		attachPaths = append(attachPaths, p)
	}
	outPath := filepath.Join(tmp, "bundle.pdf")
	conf.ValidationMode = pdfmodel.ValidationRelaxed
	if err := pdfapi.AddAttachmentsFile(blankPath, outPath, attachPaths, false, conf); err != nil {
		t.Fatalf("AddAttachmentsFile: %v", err)
	}
	out, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifyEvidenceBundle_HappyPath(t *testing.T) {
	bundle := buildTestBundle(t, nil)
	report := VerifyEvidenceBundle(bundle)
	if !report.OK {
		t.Fatalf("expected ok report, got %#v", report)
	}
	if !report.SignatureValid {
		t.Fatalf("expected signature_valid, note=%q", report.SignatureNote)
	}
	if report.DocumentID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("document_id = %q", report.DocumentID)
	}
	if len(report.Checks) < 5 {
		t.Errorf("expected 5+ hash checks, got %d", len(report.Checks))
	}
	for _, c := range report.Checks {
		if !c.OK {
			t.Errorf("check %s failed: %#v", c.Name, c)
		}
	}
}

func TestVerifyEvidenceBundle_TamperedPayload(t *testing.T) {
	bundle := buildTestBundle(t, func(files map[string][]byte) {
		// Replace the signed payload with different bytes; the signature
		// no longer binds and the hash no longer matches the manifest.
		files["audit-cert-payload.txt"] = []byte("evil tampered payload")
	})
	report := VerifyEvidenceBundle(bundle)
	if report.OK {
		t.Fatal("expected NOT ok when payload is tampered")
	}
	if report.SignatureValid {
		t.Fatal("expected signature_valid=false when payload is tampered")
	}
	found := false
	for _, c := range report.Checks {
		if c.Name == "audit-cert-payload.txt" && !c.OK {
			found = true
		}
	}
	if !found {
		t.Error("expected the payload check itself to be marked not-ok")
	}
}

func TestVerifyEvidenceBundle_TamperedSignature(t *testing.T) {
	bundle := buildTestBundle(t, func(files map[string][]byte) {
		// Flip one byte of the base64 signature; the bytes still look
		// like base64 so the verifier reaches ed25519.Verify, which
		// will then reject the now-wrong signature.
		sig := files["audit-cert-signature.txt"]
		if len(sig) > 0 {
			sig = append([]byte{}, sig...)
			if sig[0] == 'A' {
				sig[0] = 'B'
			} else {
				sig[0] = 'A'
			}
			files["audit-cert-signature.txt"] = sig
		}
	})
	report := VerifyEvidenceBundle(bundle)
	if report.OK {
		t.Fatal("expected NOT ok when signature is tampered")
	}
	if report.SignatureValid {
		t.Fatal("expected signature_valid=false when signature is tampered")
	}
}

func TestVerifyEvidenceBundle_MissingManifest(t *testing.T) {
	bundle := buildTestBundle(t, func(files map[string][]byte) {
		delete(files, "manifest.json")
	})
	report := VerifyEvidenceBundle(bundle)
	if report.OK {
		t.Fatal("expected NOT ok without manifest")
	}
	joined := strings.Join(report.Errors, " | ")
	if !strings.Contains(joined, "manifest.json missing") {
		t.Errorf("expected manifest-missing error, got: %s", joined)
	}
}

func TestVerifyEvidenceBundle_NotAPDF(t *testing.T) {
	report := VerifyEvidenceBundle([]byte("not a pdf"))
	if report.OK {
		t.Fatal("expected NOT ok for garbage input")
	}
	if len(report.Errors) == 0 {
		t.Fatal("expected at least one error for garbage input")
	}
}

func TestPemPublicKeyToBase64(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		want  string
		isErr bool
	}{
		{
			name: "pem wrapped",
			in:   "-----BEGIN PUBLIC KEY-----\nABCDEF\nGHIJ\n-----END PUBLIC KEY-----\n",
			want: "ABCDEFGHIJ",
		},
		{
			name: "bare base64",
			in:   "ABCDEFGHIJ",
			want: "ABCDEFGHIJ",
		},
		{
			name:  "empty",
			in:    "",
			isErr: true,
		},
		{
			name:  "markers malformed",
			in:    "-----BEGIN PUBLIC KEY-----only-start",
			isErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := pemPublicKeyToBase64([]byte(c.in))
			if c.isErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}
}

// Cross-check: the standalone sign.Verify helper used inside
// VerifyEvidenceBundle should agree with a direct ed25519 verify against
// the same domain string. If this ever drifts, every bundle in
// production stops verifying, so lock it down.
func TestSignVerifyDomainSeparator(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	payload := "test payload bytes"
	digest := sha256.Sum256(append([]byte("hash:audit-cert:v1:"), []byte(payload)...))
	sigB64 := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, digest[:]))
	if !sign.Verify(pubB64, payload, sigB64) {
		t.Fatal("sign.Verify rejected what direct ed25519 just signed")
	}
}

var _ = bytes.NewReader // keep bytes import even if codepath changes
