// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	pdfmodel "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"

	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/sign"
)

// handleVerifyKey returns the org's audit-cert public key in base64. Used
// by the public /verify page on the marketing site (and by anyone who
// wants to verify a Hash-issued audit certificate offline). Public
// route ,  no auth required because the public key IS public by design.
func (s *Server) handleVerifyKey(w http.ResponseWriter, r *http.Request) {
	if s.Sign == nil || s.Sign.Signer == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"public_key_b64": "",
			"algorithm":      "ed25519",
			"note":           "no signer configured on this Hash instance",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"public_key_b64":           s.Sign.Signer.PublicKeyBase64(),
		"public_key_hex":           s.Sign.Signer.PublicKeyHex(),
		"trusted_public_keys_b64":  s.EvidenceTrustedPublicKeys,
		"manifest_public_keys_b64": s.EvidenceManifestPublicKeys,
		"algorithm":                "ed25519",
		"domain":                   "hash:audit-cert:v1",
		"hash":                     "SHA-256",
		"how_to_verify":            "ed25519.verify(pub, sha256('hash:audit-cert:v1:' || cert_html), sig)",
	})
}

type verifyInput struct {
	PublicKeyB64 string `json:"public_key_b64"`
	Payload      string `json:"payload"`
	SignatureB64 string `json:"signature_b64"`
}

// handleVerify checks an arbitrary (pub, payload, signature) tuple. Public
// endpoint so the marketing page can post user-supplied values from a
// downloaded audit certificate and confirm authenticity in one click.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var in verifyInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.PublicKeyB64 == "" || in.Payload == "" || in.SignatureB64 == "" {
		writeError(w, http.StatusBadRequest, "public_key_b64, payload, signature_b64 all required")
		return
	}
	ok := sign.Verify(in.PublicKeyB64, in.Payload, in.SignatureB64)
	trusted := evidenceKeyIsTrusted(in.PublicKeyB64, s.EvidenceTrustedPublicKeys)
	writeJSON(w, http.StatusOK, map[string]any{
		"valid": ok, "issuer_trusted": trusted, "authentic_hash_evidence": ok && trusted,
	})
}

// VerifyBundleReport is the shape returned by handleVerifyBundle. Each
// check has a green/red boolean + the expected and actual hash so a UI
// can render exactly which artifact diverged.
type VerifyBundleReport struct {
	OK                          bool                `json:"ok"`
	DocumentID                  string              `json:"document_id"`
	DocumentName                string              `json:"document_name"`
	Issuer                      string              `json:"issuer"`
	GeneratedAt                 string              `json:"generated_at"`
	CompletionEffectiveAt       string              `json:"completion_effective_at,omitempty"`
	SignatureValid              bool                `json:"signature_valid"`
	SignatureNote               string              `json:"signature_note,omitempty"`
	ManifestSignatureValid      bool                `json:"manifest_signature_valid"`
	KeyTrusted                  bool                `json:"key_trusted"`
	ManifestKeyTrusted          bool                `json:"manifest_key_trusted"`
	CertificateKeyTrusted       bool                `json:"certificate_key_trusted"`
	ManifestSigningKeySHA256    string              `json:"manifest_signing_key_sha256,omitempty"`
	CertificateSigningKeySHA256 string              `json:"certificate_signing_key_sha256,omitempty"`
	PreFinalChainHeadSHA256     string              `json:"pre_final_chain_head_sha256,omitempty"`
	PreFinalChainHeadAt         string              `json:"pre_final_chain_head_created_at,omitempty"`
	ManifestPublicKeyB64        string              `json:"manifest_public_key_b64,omitempty"`
	CertificatePublicKeyB64     string              `json:"certificate_public_key_b64,omitempty"`
	Checks                      []VerifyBundleCheck `json:"checks"`
	Manifest                    json.RawMessage     `json:"manifest,omitempty"`
	Errors                      []string            `json:"errors,omitempty"`
	Warnings                    []string            `json:"warnings,omitempty"`
}

type VerifyBundleCheck struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Detail   string `json:"detail,omitempty"`
}

const maxVerifyBundleSize = 160 * 1024 * 1024 // exact final (<=128 MiB) + bounded evidence attachments

// handleVerifyBundle accepts a multipart upload of a Hash evidence
// bundle PDF, extracts the attachments via pdfcpu, then verifies
//
//   - every attachment's SHA-256 matches the issuer-signed manifest
//   - the exact final-pdf.pdf digest matches the signed certificate claim
//   - both signatures validate under a locally trusted Hash issuer key
//
// Public endpoint with no auth. The verification is purely cryptographic;
// nothing about the request is correlated to an org or user. Anyone who
// downloads the bundle (auditor, regulator, opposing counsel) can post it
// here and get a structured pass/fail report.
func (s *Server) handleVerifyBundle(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxVerifyBundleSize)
	if err := r.ParseMultipartForm(maxVerifyBundleSize); err != nil {
		writeError(w, http.StatusBadRequest, "bundle too large or malformed multipart")
		return
	}
	f, _, err := r.FormFile("bundle")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing 'bundle' file field")
		return
	}
	defer f.Close()
	pdfBytes, err := io.ReadAll(f)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read bundle: "+err.Error())
		return
	}
	report := VerifyEvidenceBundleWithTrust(pdfBytes, EvidenceTrustSet{
		ManifestPublicKeys:    s.EvidenceManifestPublicKeys,
		CertificatePublicKeys: s.EvidenceTrustedPublicKeys,
	})
	writeJSON(w, http.StatusOK, report)
}

// EvidenceTrustSet separates current export authority from historical
// certificate verification. Retiring a ceremony key must not leave it able to
// sign fresh manifests after rotation.
type EvidenceTrustSet struct {
	ManifestPublicKeys    []string
	CertificatePublicKeys []string
}

// VerifyEvidenceBundle is the testable core. Takes the bundle PDF bytes,
// using one trust list for both roles for backwards-compatible test/CLI use.
// Production callers must use VerifyEvidenceBundleWithTrust.
func VerifyEvidenceBundle(pdfBytes []byte, trustedPublicKeys ...string) VerifyBundleReport {
	return VerifyEvidenceBundleWithTrust(pdfBytes, EvidenceTrustSet{
		ManifestPublicKeys: trustedPublicKeys, CertificatePublicKeys: trustedPublicKeys,
	})
}

// VerifyEvidenceBundleWithTrust is the production verification core with
// role-separated issuer trust.
func VerifyEvidenceBundleWithTrust(pdfBytes []byte, trust EvidenceTrustSet) VerifyBundleReport {
	report := VerifyBundleReport{Checks: []VerifyBundleCheck{}}
	conf := pdfmodel.NewDefaultConfiguration()
	conf.ValidationMode = pdfmodel.ValidationRelaxed
	atts, err := pdfapi.ExtractAttachmentsRaw(bytes.NewReader(pdfBytes), "", nil, conf)
	if err != nil {
		report.Errors = append(report.Errors, "extract attachments: "+err.Error())
		return report
	}
	// Decompression-bomb guard: a malicious bundle can ship a tiny compressed
	// attachment that inflates to gigabytes. Cap each attachment and the
	// aggregate. io.LimitReader returns EOF at the cap (not an error), so the
	// explicit length check is what flags the bomb.
	const maxOrdinaryAttachmentBytes = 16 << 20
	const maxFinalPDFAttachmentBytes = 128 << 20
	const maxTotalAttachmentBytes = 160 << 20
	var totalAttachmentBytes int64
	files := map[string][]byte{}
	for _, a := range atts {
		if _, duplicate := files[a.FileName]; duplicate {
			report.Errors = append(report.Errors, "duplicate attachment name: "+a.FileName)
			return report
		}
		limit := int64(maxOrdinaryAttachmentBytes)
		if a.FileName == "final-pdf.pdf" {
			limit = maxFinalPDFAttachmentBytes
		}
		raw, err := io.ReadAll(io.LimitReader(a, limit+1))
		if err != nil {
			report.Errors = append(report.Errors, "read "+a.FileName+": "+err.Error())
			continue
		}
		if int64(len(raw)) > limit {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: attachment exceeds %d-byte decompressed limit", a.FileName, limit))
			return report
		}
		totalAttachmentBytes += int64(len(raw))
		if totalAttachmentBytes > maxTotalAttachmentBytes {
			report.Errors = append(report.Errors, "bundle attachments exceed aggregate decompressed limit")
			return report
		}
		files[a.FileName] = raw
	}
	manifestRaw, ok := files["manifest.json"]
	if !ok {
		report.Errors = append(report.Errors, "manifest.json missing from bundle attachments")
		return report
	}
	report.Manifest = json.RawMessage(manifestRaw)
	var manifest evidence.Manifest
	decoder := json.NewDecoder(bytes.NewReader(manifestRaw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		report.Errors = append(report.Errors, "parse manifest: "+err.Error())
		return report
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		report.Errors = append(report.Errors, "parse manifest: trailing JSON value")
		return report
	}
	if manifest.SchemaVersion != evidence.LegacyManifestSchemaVersion && manifest.SchemaVersion != evidence.CurrentManifestSchemaVersion {
		report.Errors = append(report.Errors, fmt.Sprintf("unsupported evidence manifest schema_version %d", manifest.SchemaVersion))
	}
	if manifest.SchemaVersion == evidence.CurrentManifestSchemaVersion {
		completionEffectiveAt, completionErr := time.Parse(time.RFC3339Nano, manifest.CompletionEffectiveAt)
		if completionErr != nil || completionEffectiveAt.IsZero() || completionEffectiveAt.UTC().Format(time.RFC3339Nano) != manifest.CompletionEffectiveAt {
			report.Errors = append(report.Errors, "manifest completion_effective_at is not canonical UTC RFC3339")
		}
	} else if manifest.SchemaVersion == evidence.LegacyManifestSchemaVersion && manifest.CompletionEffectiveAt != "" {
		report.Errors = append(report.Errors, "legacy evidence manifest must not declare completion_effective_at")
	}
	if manifest.ManifestSigDomain != "hash:evidence-manifest:v1" {
		report.Errors = append(report.Errors, "manifest signature domain is missing or unsupported")
	}
	if manifest.SignatureAlgorithm != "ed25519" || manifest.SignatureDomain != "hash:audit-cert:v1" {
		report.Errors = append(report.Errors, "certificate signature algorithm or domain is unsupported")
	}
	generatedAt, generatedAtErr := time.Parse(time.RFC3339Nano, manifest.GeneratedAt)
	if generatedAtErr != nil || generatedAt.IsZero() || generatedAt.UTC().Format(time.RFC3339Nano) != manifest.GeneratedAt {
		report.Errors = append(report.Errors, "manifest generated_at is not canonical UTC RFC3339")
	}
	report.DocumentID = manifest.DocumentID
	report.DocumentName = manifest.DocumentName
	report.Issuer = manifest.Issuer
	report.GeneratedAt = manifest.GeneratedAt
	report.CompletionEffectiveAt = manifest.CompletionEffectiveAt
	report.ManifestSigningKeySHA256 = manifest.ManifestSigningKeySHA256
	report.CertificateSigningKeySHA256 = manifest.CertificateSigningKeySHA256

	addCheck := func(name, expected string, actualBytes []byte, present bool) {
		check := VerifyBundleCheck{Name: name, Expected: expected}
		if !validSHA256Hex(expected) {
			check.Detail = "manifest SHA-256 is missing or malformed"
			report.Checks = append(report.Checks, check)
			return
		}
		if !present {
			check.Detail = "attachment missing from bundle"
			report.Checks = append(report.Checks, check)
			return
		}
		sum := sha256.Sum256(actualBytes)
		check.Actual = hex.EncodeToString(sum[:])
		check.OK = (check.Actual == expected)
		report.Checks = append(report.Checks, check)
	}
	finalPDFBytes, finalPDFPresent := files["final-pdf.pdf"]
	addCheck("final-pdf.pdf", manifest.FinalPDFSHA256, finalPDFBytes, finalPDFPresent)
	eventsBytes, eventsPresent := files["events.json"]
	addCheck("events.json", manifest.EventsSHA256, eventsBytes, eventsPresent)
	versionsBytes, versionsPresent := files["versions.json"]
	addCheck("versions.json", manifest.VersionsSHA256, versionsBytes, versionsPresent)
	manifestPubKeyBytes, manifestPubKeyPresent := files["manifest-public-key.pem"]
	addCheck("manifest-public-key.pem", manifest.ManifestPublicKeyPEMSHA256, manifestPubKeyBytes, manifestPubKeyPresent)
	certificatePubKeyBytes, certificatePubKeyPresent := files["certificate-public-key.pem"]
	addCheck("certificate-public-key.pem", manifest.CertificatePublicKeyPEMSHA256, certificatePubKeyBytes, certificatePubKeyPresent)
	certPDFBytes, certPDFPresent := files["audit-cert.pdf"]
	addCheck("audit-cert.pdf", manifest.AuditCertSHA256, certPDFBytes, certPDFPresent)
	payloadBytes, payloadPresent := files["audit-cert-payload.txt"]
	addCheck("audit-cert-payload.txt", manifest.CertPayloadSHA256, payloadBytes, payloadPresent)
	signatureBytes, signaturePresent := files["audit-cert-signature.txt"]
	addCheck("audit-cert-signature.txt", manifest.CertSignatureSHA256, signatureBytes, signaturePresent)
	declaredAttachments := map[string]struct{}{
		"manifest.json": {}, "final-pdf.pdf": {}, "events.json": {}, "versions.json": {},
		"manifest-public-key.pem": {}, "certificate-public-key.pem": {},
		"audit-cert.pdf": {}, "audit-cert-payload.txt": {}, "audit-cert-signature.txt": {},
	}
	if len(manifest.QTSP) > 0 {
		report.Warnings = append(report.Warnings, "Legacy QTSP attachment hashes were integrity-checked only; Hash does not validate these records as QES, establish certificate trust or document-digest binding, or assert legal effect")
	}
	for _, qtsp := range manifest.QTSP {
		if qtsp.CertChainAttachment == "" || path.Base(qtsp.CertChainAttachment) != qtsp.CertChainAttachment {
			report.Errors = append(report.Errors, "QTSP certificate-chain attachment name is unsafe")
			continue
		}
		if _, duplicate := declaredAttachments[qtsp.CertChainAttachment]; duplicate {
			report.Errors = append(report.Errors, "duplicate or reserved QTSP attachment name: "+qtsp.CertChainAttachment)
			continue
		}
		declaredAttachments[qtsp.CertChainAttachment] = struct{}{}
		raw, present := files[qtsp.CertChainAttachment]
		addCheck(qtsp.CertChainAttachment, qtsp.CertChainSHA256, raw, present)
	}
	if manifest.OpenTimestamps != nil {
		// The current format neither binds the proof bytes nor validates the OTS
		// calendar path. Keep the signed Hash evidence verdict independent from
		// this development-only extension, but make its unverified status
		// impossible for callers to mistake for a trusted timestamp claim.
		if manifest.OpenTimestamps.OTSFilename != "cert.ots" {
			report.Errors = append(report.Errors, "OpenTimestamps attachment name is unsupported")
		} else {
			declaredAttachments["cert.ots"] = struct{}{}
			if _, present := files["cert.ots"]; present {
				report.Warnings = append(report.Warnings, "cert.ots is an unverified development-only attachment; the Hash verdict does not validate or claim an external timestamp")
			} else {
				report.Warnings = append(report.Warnings, "manifest declares cert.ots but the unverified optional attachment is missing; the Hash verdict covers only core signed evidence")
			}
		}
	}
	for name := range files {
		if _, declared := declaredAttachments[name]; !declared {
			report.Errors = append(report.Errors, "undeclared attachment in evidence bundle: "+name)
		}
	}

	// The export manifest and ceremony certificate are independently verified.
	// After key rotation they are expected to use different trusted issuer keys.
	// Keys carried by the bundle establish identity only when pinned locally.
	if manifestPubKeyPresent {
		pubB64, pkErr := pemPublicKeyToBase64(manifestPubKeyBytes)
		if pkErr != nil {
			report.Errors = append(report.Errors, "manifest public key: "+pkErr.Error())
		} else {
			report.ManifestPublicKeyB64 = pubB64
			fingerprint, fpErr := evidence.Ed25519PublicKeyFingerprint(manifestPubKeyBytes)
			if fpErr != nil {
				report.Errors = append(report.Errors, "manifest public key fingerprint: "+fpErr.Error())
			} else if fingerprint != manifest.ManifestSigningKeySHA256 {
				report.Errors = append(report.Errors, "manifest signing-key fingerprint does not match manifest-public-key.pem")
			}
			report.ManifestKeyTrusted = evidenceKeyIsTrusted(pubB64, trust.ManifestPublicKeys)
			if !report.ManifestKeyTrusted {
				report.Errors = append(report.Errors, "manifest signing key is not trusted by this Hash verifier")
			}
			canonical, canonicalErr := evidence.CanonicalManifestForSignature(manifest)
			if canonicalErr != nil {
				report.Errors = append(report.Errors, "canonicalize manifest: "+canonicalErr.Error())
			} else {
				report.ManifestSignatureValid = sign.VerifyEvidenceManifest(pubB64, canonical, manifest.ManifestSignature)
				if !report.ManifestSignatureValid {
					report.Errors = append(report.Errors, "evidence manifest signature is invalid")
				}
			}
		}
	}
	if payloadPresent && signaturePresent && certificatePubKeyPresent {
		pubB64, pkErr := pemPublicKeyToBase64(certificatePubKeyBytes)
		if pkErr != nil {
			report.Errors = append(report.Errors, "certificate public key: "+pkErr.Error())
		} else {
			report.CertificatePublicKeyB64 = pubB64
			fingerprint, fpErr := evidence.Ed25519PublicKeyFingerprint(certificatePubKeyBytes)
			if fpErr != nil {
				report.Errors = append(report.Errors, "certificate public key fingerprint: "+fpErr.Error())
			} else if fingerprint != manifest.CertificateSigningKeySHA256 {
				report.Errors = append(report.Errors, "certificate signing-key fingerprint does not match certificate-public-key.pem")
			}
			report.CertificateKeyTrusted = evidenceKeyIsTrusted(pubB64, trust.CertificatePublicKeys)
			if !report.CertificateKeyTrusted {
				report.Errors = append(report.Errors, "certificate signing key is not trusted by this Hash verifier")
			}
			report.SignatureValid = sign.Verify(pubB64, string(payloadBytes), string(signatureBytes))
			if !report.SignatureValid {
				report.SignatureNote = "ed25519 verify failed: signature does not bind to payload under the certificate issuer key"
			}
		}
	} else {
		report.SignatureNote = "cert payload, signature, or public key missing - cannot run ed25519 verify"
	}
	report.KeyTrusted = report.ManifestKeyTrusted && report.CertificateKeyTrusted

	if payloadPresent {
		commitments, claimErr := evidence.ParseCertificateCommitments(payloadBytes)
		if claimErr != nil {
			report.Errors = append(report.Errors, claimErr.Error())
		} else {
			completionOK := manifest.SchemaVersion == evidence.LegacyManifestSchemaVersion && commitments.CompletionEffectiveAt == ""
			completionDetail := "legacy schema has no signed completion-effective timestamp"
			if manifest.SchemaVersion == evidence.CurrentManifestSchemaVersion {
				completionOK = commitments.CompletionEffectiveAt != "" && commitments.CompletionEffectiveAt == manifest.CompletionEffectiveAt
				completionDetail = "signed certificate and signed export manifest completion-effective timestamps must agree"
			}
			report.Checks = append(report.Checks, VerifyBundleCheck{
				Name: "signed-completion-effective-at", Expected: commitments.CompletionEffectiveAt,
				Actual: manifest.CompletionEffectiveAt, OK: completionOK, Detail: completionDetail,
			})
			nameDigest := sha256.Sum256([]byte(manifest.DocumentName))
			identityActual := manifest.DocumentID + "/" + manifest.OrgID + "/" + hex.EncodeToString(nameDigest[:])
			identityExpected := commitments.DocumentID + "/" + commitments.OrgID + "/" + commitments.DocumentNameSHA256
			report.Checks = append(report.Checks, VerifyBundleCheck{
				Name: "signed-document-identity", Expected: identityExpected, Actual: identityActual,
				OK:     identityActual == identityExpected,
				Detail: "signed certificate document/org/name commitments must match the signed export manifest",
			})
			actual := ""
			if finalPDFPresent {
				sum := sha256.Sum256(finalPDFBytes)
				actual = hex.EncodeToString(sum[:])
			}
			report.Checks = append(report.Checks, VerifyBundleCheck{
				Name: "signed-final-pdf-claim", Expected: commitments.FinalPDFSHA256, Actual: actual,
				OK:     finalPDFPresent && actual == commitments.FinalPDFSHA256 && manifest.FinalPDFSHA256 == commitments.FinalPDFSHA256,
				Detail: "certificate claim, signed manifest, and exact final-pdf.pdf must agree",
			})
			report.PreFinalChainHeadSHA256 = commitments.PreFinalChainHeadSHA256
			report.PreFinalChainHeadAt = commitments.PreFinalChainHeadCreatedAt
			eventsOK := eventsPresent
			eventsActual := ""
			eventsDetail := "every canonical row hash and the exact signed document-event set must verify"
			if eventsOK {
				if err := evidence.VerifyCeremonyEventsJSON(eventsBytes, manifest.DocumentID, manifest.OrgID, commitments.DocumentEventsSHA256, commitments.DocumentEventsCount); err != nil {
					eventsOK = false
					eventsDetail = err.Error()
				} else {
					eventsActual = commitments.DocumentEventsSHA256
				}
			}
			report.Checks = append(report.Checks, VerifyBundleCheck{
				Name: "signed-document-events-claim", Expected: commitments.DocumentEventsSHA256,
				Actual: eventsActual, OK: eventsOK, Detail: eventsDetail,
			})
		}
	}

	report.OK = report.SignatureValid && report.ManifestSignatureValid && report.KeyTrusted && len(report.Errors) == 0
	for _, c := range report.Checks {
		if !c.OK {
			report.OK = false
			break
		}
	}
	return report
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func evidenceKeyIsTrusted(publicKeyB64 string, trusted []string) bool {
	actual, err := decodeTrustedEd25519Key(publicKeyB64)
	if err != nil || len(actual) != ed25519.PublicKeySize {
		return false
	}
	for _, candidate := range trusted {
		expected, err := decodeTrustedEd25519Key(strings.TrimSpace(candidate))
		if err == nil && len(expected) == ed25519.PublicKeySize && subtle.ConstantTimeCompare(actual, expected) == 1 {
			return true
		}
	}
	return false
}

func decodeTrustedEd25519Key(value string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("invalid base64 public key")
}

// pemPublicKeyToBase64 unwraps the PEM lines into the raw base64 the
// /verify endpoint expects. We accept either a PEM-wrapped key or a bare
// base64 string so a reviewer can paste either form into the manual
// verify form.
func pemPublicKeyToBase64(pemBytes []byte) (string, error) {
	s := string(pemBytes)
	if !bytes.Contains(pemBytes, []byte("BEGIN PUBLIC KEY")) {
		trimmed := stripWhitespace(s)
		if trimmed == "" {
			return "", errors.New("public key is empty")
		}
		return trimmed, nil
	}
	// Production emits SPKI/DER (x509.MarshalPKIXPublicKey), whose PEM body
	// base64-decodes to 44 bytes, but sign.Verify wants the raw 32-byte ed25519
	// key. Parse the SPKI and re-emit the raw key so the in-product offline
	// verifier accepts the exact bundle the product produces. (Older bundles
	// wrapped a raw 32-byte key in PEM markers; the len==32 fallback keeps them
	// verifiable too.)
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", errors.New("public key PEM markers malformed")
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return "", fmt.Errorf("public key is %T, want ed25519", pub)
		}
		return base64.StdEncoding.EncodeToString(edPub), nil
	}
	if len(block.Bytes) == ed25519.PublicKeySize {
		return base64.StdEncoding.EncodeToString(block.Bytes), nil
	}
	return "", errors.New("public key PEM is neither SPKI nor a raw ed25519 key")
}

func stripWhitespace(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		b = append(b, c)
	}
	return string(b)
}
