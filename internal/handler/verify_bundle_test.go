// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	pdfmodel "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	pdftypes "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/sign"
)

// buildTestBundle assembles a synthetic Hash evidence bundle: a blank
// A4 PDF carrying a manifest + payload + signature + public key +
// events/versions attachments, signed with a freshly-minted ed25519
// signer. The output bytes are what handleVerifyBundle would receive.
func buildTestBundle(t *testing.T, mutate func(map[string][]byte)) ([]byte, string) {
	t.Helper()
	signer, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	bundle := buildTestBundleWithSigners(t, signer, signer, mutate)
	return bundle, signer.PublicKeyBase64()
}

func buildTestBundleWithSigners(t *testing.T, certificateSigner, manifestSigner *sign.CertSigner, mutate func(map[string][]byte)) []byte {
	t.Helper()
	return buildTestBundleWithSchema(t, certificateSigner, manifestSigner, evidence.CurrentManifestSchemaVersion, mutate)
}

func buildTestBundleWithSchema(t *testing.T, certificateSigner, manifestSigner *sign.CertSigner, schemaVersion int, mutate func(map[string][]byte)) []byte {
	t.Helper()
	tmp := t.TempDir()
	conf := pdfmodel.NewDefaultConfiguration()
	ctx, err := pdfcpu.CreateContextWithXRefTable(conf, pdftypes.PaperSize["A4"])
	if err != nil {
		t.Fatal(err)
	}
	blankPath := filepath.Join(tmp, "blank.pdf")
	bf, err := os.Create(blankPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pdfapi.WriteContext(ctx, bf); err != nil {
		t.Fatal(err)
	}
	if err := bf.Close(); err != nil {
		t.Fatal(err)
	}
	finalPDF, err := os.ReadFile(blankPath)
	if err != nil {
		t.Fatal(err)
	}
	finalSum := sha256.Sum256(finalPDF)
	finalHex := hex.EncodeToString(finalSum[:])

	documentID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	orgID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	createdAt := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	event := &generated.Event{
		ID:            uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		OrgID:         orgID,
		DocumentID:    pgtype.UUID{Bytes: documentID, Valid: true},
		Kind:          "document.signed",
		PayloadJson:   json.RawMessage(`{"method":"ses"}`),
		PayloadHashed: []byte(`{"method":"ses"}`),
		CreatedAt:     pgtype.Timestamptz{Time: createdAt, Valid: true},
	}
	event.RowHash = audit.ChainHashRecord(audit.HashInput{
		OrgID: orgID, DocID: documentID, Kind: event.Kind,
		CreatedAt: createdAt, Payload: event.PayloadHashed,
	})
	events, eventCommitment, eventCount, err := evidence.BuildCeremonyEventsJSON(documentID, []*generated.Event{event})
	if err != nil {
		t.Fatal(err)
	}
	documentName := "Test Doc"
	documentNameHash := sha256.Sum256([]byte(documentName))
	completionEffectiveAt := "2026-05-12T00:00:01.234567Z"
	completionClaim := ""
	if schemaVersion == evidence.CurrentManifestSchemaVersion {
		completionClaim = ` data-hash-completion-effective-at="` + completionEffectiveAt + `"` +
			` data-hash-pre-final-chain-scope="organization"` +
			` data-hash-document-events-scope="ceremony-root"`
	}
	payload := []byte(`<div class="hash-cert-page"><h2>Audit Certificate</h2>` +
		`<div data-hash-document-id="` + documentID.String() + `" data-hash-org-id="` + orgID.String() +
		`" data-hash-document-name-sha256="` + hex.EncodeToString(documentNameHash[:]) +
		`" data-hash-final-pdf-sha256="` + finalHex + `"` + completionClaim + `></div>` +
		`<div data-hash-pre-final-chain-head-sha256="` + strings.Repeat("a", 64) + `" ` +
		`data-hash-pre-final-chain-head-created-at="2026-05-12T00:00:00Z" ` +
		`data-hash-document-events-sha256="` + eventCommitment + `" ` +
		`data-hash-document-events-count="` + fmt.Sprintf("%d", eventCount) + `"></div></div>`)
	signature := []byte(certificateSigner.SignPayload(payload))

	versions := []byte(`{"versions":[],"count":0}`)
	certPDF := append([]byte(nil), finalPDF...)
	manifestPubKeyPEM := []byte(manifestSigner.PublicKeyPEM())
	certificatePubKeyPEM := []byte(certificateSigner.PublicKeyPEM())

	hash := func(b []byte) string {
		s := sha256.Sum256(b)
		return hex.EncodeToString(s[:])
	}
	manifestFingerprint, err := evidence.Ed25519PublicKeyFingerprint(manifestPubKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	certificateFingerprint, err := evidence.Ed25519PublicKeyFingerprint(certificatePubKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	manifest := evidence.Manifest{
		SchemaVersion:                 schemaVersion,
		DocumentID:                    documentID.String(),
		OrgID:                         orgID.String(),
		DocumentName:                  documentName,
		Issuer:                        "Hash Test",
		GeneratedAt:                   "2026-05-12T00:00:00Z",
		FinalPDFSHA256:                finalHex,
		AuditCertSHA256:               hash(certPDF),
		EventsSHA256:                  hash(events),
		VersionsSHA256:                hash(versions),
		ManifestPublicKeyPEMSHA256:    hash(manifestPubKeyPEM),
		ManifestSigningKeySHA256:      manifestFingerprint,
		CertificatePublicKeyPEMSHA256: hash(certificatePubKeyPEM),
		CertificateSigningKeySHA256:   certificateFingerprint,
		CertPayloadSHA256:             hash(payload),
		CertSignatureSHA256:           hash(signature),
		SignatureAlgorithm:            "ed25519",
		SignatureDomain:               "hash:audit-cert:v1",
		ManifestSigDomain:             "hash:evidence-manifest:v1",
		Bundle: evidence.BundleSummary{
			FinalPDFKey: "org/test/final.pdf", AuditCertKey: "org/test/audit.pdf",
		},
	}
	if schemaVersion == evidence.CurrentManifestSchemaVersion {
		manifest.CompletionEffectiveAt = completionEffectiveAt
	}
	canonical, err := evidence.CanonicalManifestForSignature(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ManifestSignature = manifestSigner.SignEvidenceManifest(canonical)
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	files := map[string][]byte{
		"final-pdf.pdf":              finalPDF,
		"manifest.json":              manifestJSON,
		"events.json":                events,
		"versions.json":              versions,
		"manifest-public-key.pem":    manifestPubKeyPEM,
		"certificate-public-key.pem": certificatePubKeyPEM,
		"audit-cert.pdf":             certPDF,
		"audit-cert-payload.txt":     payload,
		"audit-cert-signature.txt":   signature,
	}
	if mutate != nil {
		mutate(files)
	}

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
	bundle, trusted := buildTestBundle(t, nil)
	report := VerifyEvidenceBundle(bundle, trusted)
	if !report.OK {
		t.Fatalf("expected ok report, got %#v", report)
	}
	if !report.SignatureValid {
		t.Fatalf("expected signature_valid, note=%q", report.SignatureNote)
	}
	if !report.ManifestSignatureValid || !report.KeyTrusted {
		t.Fatalf("manifest/key trust = %v/%v", report.ManifestSignatureValid, report.KeyTrusted)
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

func TestVerifyEvidenceBundleSupportsLegacySchemaV2WithoutCompletionClaim(t *testing.T) {
	signer, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	bundle := buildTestBundleWithSchema(t, signer, signer, evidence.LegacyManifestSchemaVersion, nil)
	report := VerifyEvidenceBundle(bundle, signer.PublicKeyBase64())
	if !report.OK {
		t.Fatalf("legacy schema-v2 bundle should remain verifiable: %+v", report)
	}
}

func TestVerifyEvidenceBundleRejectsResignedCompletionTimestampRewrite(t *testing.T) {
	certificateSigner, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	manifestSigner, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	bundle := buildTestBundleWithSigners(t, certificateSigner, manifestSigner, func(files map[string][]byte) {
		var manifest evidence.Manifest
		if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
			t.Fatal(err)
		}
		manifest.CompletionEffectiveAt = "2026-05-12T00:00:02.234567Z"
		canonical, err := evidence.CanonicalManifestForSignature(manifest)
		if err != nil {
			t.Fatal(err)
		}
		manifest.ManifestSignature = manifestSigner.SignEvidenceManifest(canonical)
		files["manifest.json"], err = json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
	})
	report := VerifyEvidenceBundle(bundle, certificateSigner.PublicKeyBase64(), manifestSigner.PublicKeyBase64())
	if report.OK || !report.ManifestSignatureValid {
		t.Fatalf("re-signed completion timestamp rewrite must fail certificate commitment: %+v", report)
	}
	found := false
	for _, check := range report.Checks {
		if check.Name == "signed-completion-effective-at" && !check.OK {
			found = true
		}
	}
	if !found {
		t.Fatal("completion-effective timestamp mismatch was not reported")
	}
}

func TestVerifyEvidenceBundleReportsUnverifiedOpenTimestampsAsWarning(t *testing.T) {
	signer, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	bundle := buildTestBundleWithSigners(t, signer, signer, func(files map[string][]byte) {
		var manifest evidence.Manifest
		if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
			t.Fatal(err)
		}
		manifest.OpenTimestamps = &evidence.AnchorSummary{
			Digest: strings.Repeat("a", sha256.Size*2), OTSFilename: "cert.ots", StampedAt: "2026-05-12T00:00:00Z",
		}
		manifest.ManifestSignature = ""
		canonical, err := evidence.CanonicalManifestForSignature(manifest)
		if err != nil {
			t.Fatal(err)
		}
		manifest.ManifestSignature = signer.SignEvidenceManifest(canonical)
		files["manifest.json"], err = json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		files["cert.ots"] = []byte("opaque development-only proof bytes")
	})
	report := VerifyEvidenceBundle(bundle, signer.PublicKeyBase64())
	if !report.OK {
		t.Fatalf("unverified optional timestamp must not invalidate core evidence: %+v", report)
	}
	if len(report.Errors) != 0 || len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], "unverified") {
		t.Fatalf("unexpected OTS diagnostics: errors=%v warnings=%v", report.Errors, report.Warnings)
	}
}

func TestVerifyEvidenceBundleClassifiesHistoricalQTSPMaterialAsUnverified(t *testing.T) {
	signer, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	bundle := buildTestBundleWithSigners(t, signer, signer, func(files map[string][]byte) {
		var manifest evidence.Manifest
		if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
			t.Fatal(err)
		}
		legacyChain := []byte("legacy provider chain bytes")
		chainSHA := sha256.Sum256(legacyChain)
		manifest.QTSP = []evidence.QTSPBlock{{
			Provider:            "legacy-provider",
			SessionID:           "legacy-session",
			RecipientID:         "legacy-recipient",
			CertChainSHA256:     hex.EncodeToString(chainSHA[:]),
			CertChainAttachment: "legacy-qes-chain.pem",
		}}
		manifest.ManifestSignature = ""
		canonical, err := evidence.CanonicalManifestForSignature(manifest)
		if err != nil {
			t.Fatal(err)
		}
		manifest.ManifestSignature = signer.SignEvidenceManifest(canonical)
		files["manifest.json"], err = json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		files["legacy-qes-chain.pem"] = legacyChain
	})
	report := VerifyEvidenceBundle(bundle, signer.PublicKeyBase64())
	if !report.OK {
		t.Fatalf("historical bundle core evidence should remain inspectable: %+v", report)
	}
	if len(report.Warnings) != 1 {
		t.Fatalf("warnings = %v, want one explicit legacy-QES warning", report.Warnings)
	}
	warning := report.Warnings[0]
	for _, phrase := range []string{"integrity-checked only", "does not validate", "document-digest binding", "legal effect"} {
		if !strings.Contains(warning, phrase) {
			t.Errorf("warning does not disclose %q: %s", phrase, warning)
		}
	}
}

func TestVerifyEvidenceBundleSupportsCertificateKeyRotation(t *testing.T) {
	certificateSigner, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	manifestSigner, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	bundle := buildTestBundleWithSigners(t, certificateSigner, manifestSigner, nil)
	report := VerifyEvidenceBundleWithTrust(bundle, EvidenceTrustSet{
		ManifestPublicKeys:    []string{manifestSigner.PublicKeyBase64()},
		CertificatePublicKeys: []string{certificateSigner.PublicKeyBase64(), manifestSigner.PublicKeyBase64()},
	})
	if !report.OK || !report.CertificateKeyTrusted || !report.ManifestKeyTrusted {
		t.Fatalf("rotated trusted certificate/export keys should verify: %+v", report)
	}
	if report.CertificatePublicKeyB64 == report.ManifestPublicKeyB64 {
		t.Fatal("rotation fixture unexpectedly used the same key for both signatures")
	}

	missingHistorical := VerifyEvidenceBundleWithTrust(bundle, EvidenceTrustSet{
		ManifestPublicKeys:    []string{manifestSigner.PublicKeyBase64()},
		CertificatePublicKeys: []string{manifestSigner.PublicKeyBase64()},
	})
	if missingHistorical.OK || missingHistorical.CertificateKeyTrusted || !missingHistorical.ManifestKeyTrusted {
		t.Fatalf("bundle must fail when the historical certificate key is no longer trusted: %+v", missingHistorical)
	}
}

func TestVerifyEvidenceBundleRetiredCertificateKeyCannotSignNewManifest(t *testing.T) {
	retiredSigner, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	currentSigner, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	bundle := buildTestBundleWithSigners(t, retiredSigner, retiredSigner, nil)
	report := VerifyEvidenceBundleWithTrust(bundle, EvidenceTrustSet{
		ManifestPublicKeys:    []string{currentSigner.PublicKeyBase64()},
		CertificatePublicKeys: []string{currentSigner.PublicKeyBase64(), retiredSigner.PublicKeyBase64()},
	})
	if report.OK || report.ManifestKeyTrusted || !report.CertificateKeyTrusted || !report.ManifestSignatureValid {
		t.Fatalf("retired certificate key was incorrectly granted current manifest authority: %+v", report)
	}
}

func TestVerifyEvidenceBundleRejectsTrustedManifestRelabeling(t *testing.T) {
	certificateSigner, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	manifestSigner, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	bundle := buildTestBundleWithSigners(t, certificateSigner, manifestSigner, func(files map[string][]byte) {
		var manifest evidence.Manifest
		if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
			t.Fatal(err)
		}
		manifest.DocumentName = "Relabeled Agreement"
		canonical, err := evidence.CanonicalManifestForSignature(manifest)
		if err != nil {
			t.Fatal(err)
		}
		manifest.ManifestSignature = manifestSigner.SignEvidenceManifest(canonical)
		files["manifest.json"], _ = json.MarshalIndent(manifest, "", "  ")
	})
	report := VerifyEvidenceBundle(bundle, certificateSigner.PublicKeyBase64(), manifestSigner.PublicKeyBase64())
	if report.OK || !report.ManifestSignatureValid {
		t.Fatalf("trusted export signer must not be able to relabel the signed certificate identity: %+v", report)
	}
	found := false
	for _, check := range report.Checks {
		if check.Name == "signed-document-identity" && !check.OK {
			found = true
		}
	}
	if !found {
		t.Fatal("signed document identity mismatch was not reported")
	}
}

func TestVerifyEvidenceBundleRejectsResignedCeremonyEventRewrite(t *testing.T) {
	certificateSigner, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	manifestSigner, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	bundle := buildTestBundleWithSigners(t, certificateSigner, manifestSigner, func(files map[string][]byte) {
		before := files["events.json"]
		files["events.json"] = bytes.Replace(before, []byte(`ses`), []byte(`forged`), 1)
		if bytes.Equal(before, files["events.json"]) {
			t.Fatal("test fixture did not rewrite the ceremony event")
		}
		var manifest evidence.Manifest
		if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
			t.Fatal(err)
		}
		eventsSHA := sha256.Sum256(files["events.json"])
		manifest.EventsSHA256 = hex.EncodeToString(eventsSHA[:])
		canonical, err := evidence.CanonicalManifestForSignature(manifest)
		if err != nil {
			t.Fatal(err)
		}
		manifest.ManifestSignature = manifestSigner.SignEvidenceManifest(canonical)
		files["manifest.json"], _ = json.MarshalIndent(manifest, "", "  ")
	})
	report := VerifyEvidenceBundle(bundle, certificateSigner.PublicKeyBase64(), manifestSigner.PublicKeyBase64())
	if report.OK || !report.ManifestSignatureValid {
		t.Fatalf("re-signed event rewrite must still fail the ceremony certificate commitment: %+v", report)
	}
	found := false
	for _, check := range report.Checks {
		if check.Name == "signed-document-events-claim" && !check.OK {
			found = true
		}
	}
	if !found {
		t.Fatal("signed document-event set mismatch was not reported")
	}
}

func TestVerifyEvidenceBundleRejectsSelfSignedUntrustedIssuer(t *testing.T) {
	bundle, _ := buildTestBundle(t, nil)
	report := VerifyEvidenceBundle(bundle)
	if report.OK || report.KeyTrusted {
		t.Fatalf("self-supplied issuer key must not establish Hash trust: %+v", report)
	}
}

func TestVerifyEvidenceBundleRejectsManifestAndEventsRewrite(t *testing.T) {
	bundle, trusted := buildTestBundle(t, func(files map[string][]byte) {
		files["events.json"] = []byte(`{"events":[{"forged":true}],"count":1}`)
		var manifest evidence.Manifest
		if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(files["events.json"])
		manifest.EventsSHA256 = hex.EncodeToString(sum[:])
		// The attacker can update self-declared hashes but cannot re-issue the
		// trusted Hash manifest signature.
		files["manifest.json"], _ = json.MarshalIndent(manifest, "", "  ")
	})
	report := VerifyEvidenceBundle(bundle, trusted)
	if report.OK || report.ManifestSignatureValid {
		t.Fatalf("rewritten evidence manifest was accepted: %+v", report)
	}
}

func TestVerifyEvidenceBundleRejectsDifferentFinalPDF(t *testing.T) {
	bundle, trusted := buildTestBundle(t, func(files map[string][]byte) {
		files["final-pdf.pdf"] = []byte("different contract bytes")
	})
	report := VerifyEvidenceBundle(bundle, trusted)
	if report.OK {
		t.Fatalf("certificate was accepted with a different final contract: %+v", report)
	}
	found := false
	for _, check := range report.Checks {
		if check.Name == "signed-final-pdf-claim" && !check.OK {
			found = true
		}
	}
	if !found {
		t.Fatal("signed final-PDF claim mismatch was not reported")
	}
}

func TestVerifyEvidenceBundle_TamperedPayload(t *testing.T) {
	bundle, trusted := buildTestBundle(t, func(files map[string][]byte) {
		// Replace the signed payload with different bytes; the signature
		// no longer binds and the hash no longer matches the manifest.
		files["audit-cert-payload.txt"] = []byte("evil tampered payload")
	})
	report := VerifyEvidenceBundle(bundle, trusted)
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
	bundle, trusted := buildTestBundle(t, func(files map[string][]byte) {
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
	report := VerifyEvidenceBundle(bundle, trusted)
	if report.OK {
		t.Fatal("expected NOT ok when signature is tampered")
	}
	if report.SignatureValid {
		t.Fatal("expected signature_valid=false when signature is tampered")
	}
}

func TestVerifyEvidenceBundle_MissingManifest(t *testing.T) {
	bundle, trusted := buildTestBundle(t, func(files map[string][]byte) {
		delete(files, "manifest.json")
	})
	report := VerifyEvidenceBundle(bundle, trusted)
	if report.OK {
		t.Fatal("expected NOT ok without manifest")
	}
	joined := strings.Join(report.Errors, " | ")
	if !strings.Contains(joined, "manifest.json missing") {
		t.Errorf("expected manifest-missing error, got: %s", joined)
	}
}

func TestVerifyEvidenceBundleRejectsUndeclaredAttachment(t *testing.T) {
	bundle, trusted := buildTestBundle(t, func(files map[string][]byte) {
		files["hidden-instructions.txt"] = []byte("not declared or covered by the evidence manifest")
	})
	report := VerifyEvidenceBundle(bundle, trusted)
	if report.OK || !strings.Contains(strings.Join(report.Errors, " | "), "undeclared attachment") {
		t.Fatalf("undeclared attachment was accepted: %+v", report)
	}
}

func TestEvidenceKeyTrustAcceptsConfiguredURLSafeEncoding(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	standard := base64.StdEncoding.EncodeToString(pub)
	urlSafe := base64.RawURLEncoding.EncodeToString(pub)
	if !evidenceKeyIsTrusted(standard, []string{urlSafe}) {
		t.Fatal("URL-safe trusted rotation key did not match the equivalent standard-base64 key")
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
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawB64 := base64.StdEncoding.EncodeToString(pub) // the 32-byte key sign.Verify wants
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	spkiPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
	rawPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))

	cases := []struct {
		name  string
		in    string
		want  string
		isErr bool
	}{
		{
			// Production format: SPKI DER (44-byte body) must decode to the raw key.
			name: "spki pem (production)",
			in:   spkiPEM,
			want: rawB64,
		},
		{
			// Legacy bundles wrapped the raw 32-byte key in PEM markers.
			name: "legacy raw key in pem",
			in:   rawPEM,
			want: rawB64,
		},
		{
			name: "bare base64",
			in:   rawB64,
			want: rawB64,
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
