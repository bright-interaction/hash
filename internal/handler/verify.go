package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	pdfmodel "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"

	"github.com/brightinteraction/hash/internal/sign"
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
		"public_key_b64": s.Sign.Signer.PublicKeyBase64(),
		"public_key_hex": s.Sign.Signer.PublicKeyHex(),
		"algorithm":      "ed25519",
		"domain":         "hash:audit-cert:v1",
		"hash":           "SHA-256",
		"how_to_verify":  "ed25519.verify(pub, sha256('hash:audit-cert:v1:' || cert_html), sig)",
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
	writeJSON(w, http.StatusOK, map[string]any{"valid": ok})
}

// VerifyBundleReport is the shape returned by handleVerifyBundle. Each
// check has a green/red boolean + the expected and actual hash so a UI
// can render exactly which artifact diverged.
type VerifyBundleReport struct {
	OK             bool                `json:"ok"`
	DocumentID     string              `json:"document_id"`
	DocumentName   string              `json:"document_name"`
	Issuer         string              `json:"issuer"`
	GeneratedAt    string              `json:"generated_at"`
	SignatureValid bool                `json:"signature_valid"`
	SignatureNote  string              `json:"signature_note,omitempty"`
	PublicKeyB64   string              `json:"public_key_b64,omitempty"`
	Checks         []VerifyBundleCheck `json:"checks"`
	Manifest       json.RawMessage     `json:"manifest,omitempty"`
	Errors         []string            `json:"errors,omitempty"`
}

type VerifyBundleCheck struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Detail   string `json:"detail,omitempty"`
}

const maxVerifyBundleSize = 64 * 1024 * 1024 // 64 MiB

// handleVerifyBundle accepts a multipart upload of a Hash evidence
// bundle PDF, extracts the attachments via pdfcpu, then verifies
//
//   - every attachment's SHA-256 matches the manifest
//   - the ed25519 signature over the cert payload validates against the
//     embedded public-key.pem
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
	report := VerifyEvidenceBundle(pdfBytes)
	writeJSON(w, http.StatusOK, report)
}

// VerifyEvidenceBundle is the testable core. Takes the bundle PDF bytes,
// returns a structured report. Exported so tests + future CLI tooling can
// share the same code path as the HTTP handler.
func VerifyEvidenceBundle(pdfBytes []byte) VerifyBundleReport {
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
	const maxAttachmentBytes = 16 << 20      // 16 MiB per attachment
	const maxTotalAttachmentBytes = 96 << 20 // 96 MiB aggregate
	var totalAttachmentBytes int64
	files := map[string][]byte{}
	for _, a := range atts {
		raw, err := io.ReadAll(io.LimitReader(a, maxAttachmentBytes+1))
		if err != nil {
			report.Errors = append(report.Errors, "read "+a.FileName+": "+err.Error())
			continue
		}
		if int64(len(raw)) > maxAttachmentBytes {
			report.Errors = append(report.Errors, a.FileName+": attachment exceeds 16 MiB decompressed limit")
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
	var manifest struct {
		DocumentID          string `json:"document_id"`
		DocumentName        string `json:"document_name"`
		Issuer              string `json:"issuer"`
		GeneratedAt         string `json:"generated_at"`
		EventsSHA256        string `json:"events_sha256"`
		VersionsSHA256      string `json:"versions_sha256"`
		PublicKeyPEMHash    string `json:"public_key_pem_sha256"`
		CertPayloadSHA256   string `json:"cert_payload_sha256"`
		CertSignatureSHA256 string `json:"cert_signature_sha256"`
		AuditCertSHA256     string `json:"audit_cert_sha256"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		report.Errors = append(report.Errors, "parse manifest: "+err.Error())
		return report
	}
	report.DocumentID = manifest.DocumentID
	report.DocumentName = manifest.DocumentName
	report.Issuer = manifest.Issuer
	report.GeneratedAt = manifest.GeneratedAt

	addCheck := func(name, expected string, actualBytes []byte, present bool) {
		if expected == "" && !present {
			return
		}
		check := VerifyBundleCheck{Name: name, Expected: expected}
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
	eventsBytes, eventsPresent := files["events.json"]
	addCheck("events.json", manifest.EventsSHA256, eventsBytes, eventsPresent)
	versionsBytes, versionsPresent := files["versions.json"]
	addCheck("versions.json", manifest.VersionsSHA256, versionsBytes, versionsPresent)
	pubKeyBytes, pubKeyPresent := files["public-key.pem"]
	addCheck("public-key.pem", manifest.PublicKeyPEMHash, pubKeyBytes, pubKeyPresent)
	certPDFBytes, certPDFPresent := files["audit-cert.pdf"]
	addCheck("audit-cert.pdf", manifest.AuditCertSHA256, certPDFBytes, certPDFPresent)
	payloadBytes, payloadPresent := files["audit-cert-payload.txt"]
	addCheck("audit-cert-payload.txt", manifest.CertPayloadSHA256, payloadBytes, payloadPresent)
	signatureBytes, signaturePresent := files["audit-cert-signature.txt"]
	addCheck("audit-cert-signature.txt", manifest.CertSignatureSHA256, signatureBytes, signaturePresent)

	// Cryptographic verification: ed25519 over sha256("hash:audit-cert:v1:" || payload).
	if payloadPresent && signaturePresent && pubKeyPresent {
		pubB64, pkErr := pemPublicKeyToBase64(pubKeyBytes)
		if pkErr != nil {
			report.Errors = append(report.Errors, "public key: "+pkErr.Error())
		} else {
			report.PublicKeyB64 = pubB64
			report.SignatureValid = sign.Verify(pubB64, string(payloadBytes), string(signatureBytes))
			if !report.SignatureValid {
				report.SignatureNote = "ed25519 verify failed: signature does not bind to payload under this public key"
			}
		}
	} else {
		report.SignatureNote = "cert payload, signature, or public key missing - cannot run ed25519 verify"
	}

	report.OK = report.SignatureValid && len(report.Errors) == 0
	for _, c := range report.Checks {
		if !c.OK {
			report.OK = false
			break
		}
	}
	return report
}

// pemPublicKeyToBase64 unwraps the PEM lines into the raw base64 the
// /verify endpoint expects. We accept either a PEM-wrapped key or a bare
// base64 string so a reviewer can paste either form into the manual
// verify form.
func pemPublicKeyToBase64(pem []byte) (string, error) {
	s := string(pem)
	if !bytes.Contains(pem, []byte("BEGIN PUBLIC KEY")) {
		trimmed := stripWhitespace(s)
		if trimmed == "" {
			return "", errors.New("public key is empty")
		}
		return trimmed, nil
	}
	const startMarker = "-----BEGIN PUBLIC KEY-----"
	const endMarker = "-----END PUBLIC KEY-----"
	start := bytes.Index(pem, []byte(startMarker))
	end := bytes.Index(pem, []byte(endMarker))
	if start < 0 || end < 0 || end <= start {
		return "", errors.New("public key PEM markers malformed")
	}
	body := string(pem[start+len(startMarker) : end])
	body = stripWhitespace(body)
	if body == "" {
		return "", errors.New("public key body empty")
	}
	return body, nil
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
