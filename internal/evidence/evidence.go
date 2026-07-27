// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package evidence implements Phase 10.2: court-ready evidence bundle.
//
// Builds a single PDF containing:
//
//   - The signed final PDF as the visible body.
//   - The audit certificate PDF as the next page (already concatenated
//     in Phase 3 via Gotenberg; we reuse it without re-rendering).
//   - Attached files (PDF/A-3-style embeddings) for machine readers:
//   - manifest.json     evidence manifest with hashes + signing key
//   - events.json       complete audit event timeline for the doc
//   - versions.json     version history with block-level diffs
//   - public-key.pem    ed25519 public key in PEM form
//   - cert.ots          optional OpenTimestamps proof for manifest.json
//
// Full PDF/A-3 conformance (ICC color profile, XMP /A flag, tagged
// structure) is a follow-up: pdfcpu's PDF/A validation is incomplete in
// v0.12 so we ship the bundle without claiming conformance until the
// validator is in place. The attachment-bearing shape is identical to
// what a PDF/A-3 validator expects, so the upgrade is purely additive.
package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/timeline"
	"github.com/bright-interaction/hash/internal/versions"
)

// Builder produces evidence bundles. Hold one process-wide.
type Builder struct {
	Q            *generated.Queries
	Storage      *storage.Client
	Versions     *versions.Engine
	OTSAnchor    OTSAnchor // optional; nil disables anchoring
	PublicKeyPEM string    // pre-formatted ed25519 public key in PEM
	Issuer       string    // human-readable issuer (e.g. "Hash / Bright Interaction AB")
}

// OTSAnchor is the optional OpenTimestamps client. Default impl lives in
// ots.go; tests can swap a fake.
type OTSAnchor interface {
	Stamp(ctx context.Context, digest []byte) (otsBytes []byte, err error)
}

// Manifest is the top-level JSON every reader cross-references.
type Manifest struct {
	SchemaVersion       int            `json:"schema_version"`
	GeneratedAt         string         `json:"generated_at"`
	Issuer              string         `json:"issuer"`
	DocumentID          string         `json:"document_id"`
	DocumentName        string         `json:"document_name"`
	OrgID               string         `json:"org_id"`
	FinalPDFSHA256      string         `json:"final_pdf_sha256"`
	AuditCertSHA256     string         `json:"audit_cert_sha256"`
	EventsSHA256        string         `json:"events_sha256"`
	VersionsSHA256      string         `json:"versions_sha256"`
	PublicKeyPEMHash    string         `json:"public_key_pem_sha256"`
	CertPayloadSHA256   string         `json:"cert_payload_sha256,omitempty"`
	CertSignatureSHA256 string         `json:"cert_signature_sha256,omitempty"`
	SignatureAlgorithm  string         `json:"signature_algorithm,omitempty"`
	SignatureDomain     string         `json:"signature_domain,omitempty"`
	QTSP                []QTSPBlock    `json:"qtsp,omitempty"`
	Bundle              BundleSummary  `json:"bundle"`
	OpenTimestamps      *AnchorSummary `json:"open_timestamps,omitempty"`
	Notes               string         `json:"notes,omitempty"`
}

// QTSPBlock surfaces one QES signing session's QTSP-rooted trust path so
// a forensic examiner can verify the qualified electronic signature
// without needing access to the live database. One entry per
// recipient that signed via QES.
type QTSPBlock struct {
	Provider            string `json:"provider"`
	SessionID           string `json:"session_id"`
	RecipientID         string `json:"recipient_id"`
	CompletedAt         string `json:"completed_at,omitempty"`
	CertChainSHA256     string `json:"cert_chain_pem_sha256"`
	CertChainAttachment string `json:"cert_chain_attachment"`
	SubjectCN           string `json:"subject_cn,omitempty"`
	IssuerCN            string `json:"issuer_cn,omitempty"`
	NotBefore           string `json:"not_before,omitempty"`
	NotAfter            string `json:"not_after,omitempty"`
}

type BundleSummary struct {
	FinalPDFKey  string `json:"final_pdf_key,omitempty"`
	AuditCertKey string `json:"audit_cert_key,omitempty"`
	EventCount   int    `json:"event_count"`
	VersionCount int    `json:"version_count"`
}

type AnchorSummary struct {
	Digest      string `json:"digest_sha256"`
	OTSFilename string `json:"ots_filename"`
	StampedAt   string `json:"stamped_at"`
}

// EvidenceResult is what Build returns: bytes ready to stream to the
// caller, plus the manifest object for the audit log.
type EvidenceResult struct {
	Bytes    []byte
	Manifest Manifest
	Filename string
}

// Build assembles the evidence bundle for the given document. The
// document must be in a terminal state (`completed`, `declined`,
// `voided`, `expired`) so the final PDF + cert exist; drafts are
// rejected with ErrNotTerminal.
func (b *Builder) Build(ctx context.Context, doc *generated.Document) (*EvidenceResult, error) {
	if doc == nil {
		return nil, errors.New("evidence: nil document")
	}
	if !isTerminal(doc.Status) {
		return nil, ErrNotTerminal
	}
	if !doc.FinalPdfKey.Valid || len(doc.FinalPdfSha) == 0 {
		return nil, fmt.Errorf("evidence: document has no final PDF (status=%s)", doc.Status)
	}

	// 1. Pull the final PDF from storage. It already contains the audit
	// cert as the trailing page (renderAuditCertificate is appended
	// during Sign() in Phase 3+).
	finalPDF, err := b.Storage.Get(ctx, doc.FinalPdfKey.String)
	if err != nil {
		return nil, fmt.Errorf("evidence: load final PDF: %w", err)
	}
	finalSHA := sha256.Sum256(finalPDF)

	// 2. Pull the cert separately if it lives at its own key (week 7+
	// stored the cert as a distinct asset for the /audit-cert endpoint).
	var certPDF []byte
	var certSHA [32]byte
	if doc.AuditCertKey.Valid {
		if cert, err := b.Storage.Get(ctx, doc.AuditCertKey.String); err == nil {
			certPDF = cert
			certSHA = sha256.Sum256(cert)
		}
	}

	// 2b. Phase 10.2.1: pull the exact signed payload + detached signature
	// the sign engine persisted next to the cert PDF. Drag-drop verify on
	// /verify needs these because the cert PDF is a Gotenberg render of
	// the HTML that was signed, not the bytes themselves. Documents
	// finalized before the Phase 10.2.1 cutover won't have these objects
	// in storage; the bundle still produces (with the fields zeroed) so a
	// reviewer can still inspect every other artifact.
	var certPayload []byte
	var certPayloadSHA [32]byte
	var certSignature []byte
	var certSignatureSHA [32]byte
	if doc.FinalPdfKey.Valid {
		base := stripFinalPDFSuffix(doc.FinalPdfKey.String)
		if p, err := b.Storage.Get(ctx, base+"audit.payload.txt"); err == nil {
			certPayload = p
			certPayloadSHA = sha256.Sum256(p)
		}
		if s, err := b.Storage.Get(ctx, base+"audit.signature.txt"); err == nil {
			certSignature = s
			certSignatureSHA = sha256.Sum256(s)
		}
	}

	// 3. Serialize the event timeline. Pull a generous slice; the
	// timeline package's grouping logic stays out of the bundle so a
	// forensic examiner sees raw events.
	eventRows, err := b.Q.ListEventsByDocument(ctx, generated.ListEventsByDocumentParams{
		DocumentID: pgUUIDOf(doc.ID),
		Limit:      10000,
	})
	if err != nil {
		return nil, fmt.Errorf("evidence: load events: %w", err)
	}
	events := make([]timeline.Entry, 0, len(eventRows))
	for _, ev := range eventRows {
		events = append(events, timeline.FromEvent(ev))
	}
	eventsJSON, err := json.MarshalIndent(map[string]any{
		"schema_version": 1,
		"document_id":    doc.ID.String(),
		"events":         events,
		"count":          len(events),
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	eventsSHA := sha256.Sum256(eventsJSON)

	// 4. Version history with per-step diffs.
	versionRows, _ := b.Versions.History(ctx, doc.ID, 1000)
	type versionDelta struct {
		VersionNo  int32                  `json:"version_no"`
		CreatedAt  string                 `json:"created_at"`
		CreatedVia string                 `json:"created_via"`
		Summary    string                 `json:"summary,omitempty"`
		Diff       []versions.BlockChange `json:"diff,omitempty"`
	}
	deltas := make([]versionDelta, 0, len(versionRows))
	// versionRows is newest-first; iterate so each diff compares with
	// the previous row in chronological order.
	for i := 0; i < len(versionRows); i++ {
		cur := versionRows[i]
		entry := versionDelta{
			VersionNo:  cur.VersionNo,
			CreatedAt:  cur.CreatedAt.Time.UTC().Format(time.RFC3339),
			CreatedVia: cur.CreatedVia,
			Summary:    cur.Summary,
		}
		if cur.VersionNo > 1 {
			prior, err := b.Versions.GetByNo(ctx, doc.ID, cur.VersionNo-1)
			if err == nil {
				changes, derr := versions.Diff(prior.BlockTreeJson, cur.BlockTreeJson)
				if derr == nil {
					entry.Diff = changes
				}
			}
		}
		deltas = append(deltas, entry)
	}
	versionsJSON, err := json.MarshalIndent(map[string]any{
		"schema_version": 1,
		"document_id":    doc.ID.String(),
		"versions":       deltas,
		"count":          len(deltas),
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	versionsSHA := sha256.Sum256(versionsJSON)

	// 5. Public key bytes.
	pubKeyBytes := []byte(b.PublicKeyPEM)
	pubKeySHA := sha256.Sum256(pubKeyBytes)

	// 5b. Phase 10.2.1 QTSP chain. When recipients signed via QES the
	// callback persisted the X.509 chain that anchors the qualified
	// signature; surface it in the manifest + attach the raw PEM so a
	// forensic reviewer can trace the chain to a trusted root without
	// touching the live database.
	qesSessions, qErr := b.Q.ListCompletedQESSessionsForDocument(ctx, doc.ID)
	if qErr != nil {
		slog.Warn("evidence: list QES sessions", "doc_id", doc.ID, "err", qErr)
	}
	type qesAttachment struct {
		name string
		raw  []byte
	}
	var qtspBlocks []QTSPBlock
	var qesAttachments []qesAttachment
	for i, sess := range qesSessions {
		if sess == nil || !sess.CertChainPem.Valid || sess.CertChainPem.String == "" {
			continue
		}
		chainPEM := []byte(sess.CertChainPem.String)
		chainSHA := sha256.Sum256(chainPEM)
		attachmentName := fmt.Sprintf("qes-cert-chain-%d.pem", i+1)
		block := QTSPBlock{
			Provider:            sess.Provider,
			SessionID:           sess.ID.String(),
			RecipientID:         sess.RecipientID.String(),
			CertChainSHA256:     hex.EncodeToString(chainSHA[:]),
			CertChainAttachment: attachmentName,
		}
		if sess.CompletedAt.Valid {
			block.CompletedAt = sess.CompletedAt.Time.UTC().Format(time.RFC3339)
		}
		if leaf, perr := firstCertFromPEM(chainPEM); perr == nil && leaf != nil {
			block.SubjectCN = leaf.Subject.CommonName
			block.IssuerCN = leaf.Issuer.CommonName
			block.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
			block.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
		} else if perr != nil {
			slog.Debug("evidence: parse QES leaf cert", "doc_id", doc.ID, "err", perr)
		}
		qtspBlocks = append(qtspBlocks, block)
		qesAttachments = append(qesAttachments, qesAttachment{name: attachmentName, raw: chainPEM})
	}

	// 6. Manifest before attachments so it can name its own attachment
	// sibling SHAs.
	manifest := Manifest{
		SchemaVersion:    1,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		Issuer:           b.Issuer,
		DocumentID:       doc.ID.String(),
		DocumentName:     doc.Name,
		OrgID:            doc.OrgID.String(),
		FinalPDFSHA256:   hex.EncodeToString(finalSHA[:]),
		AuditCertSHA256:  hex.EncodeToString(certSHA[:]),
		EventsSHA256:     hex.EncodeToString(eventsSHA[:]),
		VersionsSHA256:   hex.EncodeToString(versionsSHA[:]),
		PublicKeyPEMHash: hex.EncodeToString(pubKeySHA[:]),
		Bundle: BundleSummary{
			FinalPDFKey:  storageKeyOrEmpty(doc.FinalPdfKey),
			AuditCertKey: storageKeyOrEmpty(doc.AuditCertKey),
			EventCount:   len(events),
			VersionCount: len(deltas),
		},
		Notes: "Evidence bundle for offline forensic review. SHA-256 of manifest is anchored externally when OpenTimestamps is enabled.",
	}
	if len(certPayload) > 0 {
		manifest.CertPayloadSHA256 = hex.EncodeToString(certPayloadSHA[:])
		manifest.SignatureAlgorithm = "ed25519"
		manifest.SignatureDomain = "hash:audit-cert:v1"
	}
	if len(certSignature) > 0 {
		manifest.CertSignatureSHA256 = hex.EncodeToString(certSignatureSHA[:])
	}
	if len(qtspBlocks) > 0 {
		manifest.QTSP = qtspBlocks
	}

	// 7. Optional OpenTimestamps anchor on the manifest's own SHA-256.
	var otsBytes []byte
	if b.OTSAnchor != nil {
		manifestForAnchor, err := json.Marshal(manifest)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(manifestForAnchor)
		ots, err := b.OTSAnchor.Stamp(ctx, digest[:])
		if err == nil && len(ots) > 0 {
			otsBytes = ots
			manifest.OpenTimestamps = &AnchorSummary{
				Digest:      hex.EncodeToString(digest[:]),
				OTSFilename: "cert.ots",
				StampedAt:   time.Now().UTC().Format(time.RFC3339),
			}
		}
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}

	// 8. Materialize attachments to a temp dir + run pdfcpu's
	// AddAttachmentsFile. pdfcpu v0.12 requires file paths; we keep the
	// temp dir on disk for the duration of the call and clean up after.
	tmpDir, err := os.MkdirTemp("", "hash-evidence-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)
	inputPath := filepath.Join(tmpDir, "input.pdf")
	if err := os.WriteFile(inputPath, finalPDF, 0o600); err != nil {
		return nil, err
	}
	attachments := []struct {
		name string
		raw  []byte
	}{
		{"manifest.json", manifestJSON},
		{"events.json", eventsJSON},
		{"versions.json", versionsJSON},
		{"public-key.pem", pubKeyBytes},
	}
	if certPDF != nil {
		attachments = append(attachments, struct {
			name string
			raw  []byte
		}{"audit-cert.pdf", certPDF})
	}
	if len(certPayload) > 0 {
		attachments = append(attachments, struct {
			name string
			raw  []byte
		}{"audit-cert-payload.txt", certPayload})
	}
	if len(certSignature) > 0 {
		attachments = append(attachments, struct {
			name string
			raw  []byte
		}{"audit-cert-signature.txt", certSignature})
	}
	if otsBytes != nil {
		attachments = append(attachments, struct {
			name string
			raw  []byte
		}{"cert.ots", otsBytes})
	}
	for _, qa := range qesAttachments {
		attachments = append(attachments, struct {
			name string
			raw  []byte
		}{qa.name, qa.raw})
	}
	files := make([]string, 0, len(attachments))
	for _, a := range attachments {
		p := filepath.Join(tmpDir, a.name)
		if err := os.WriteFile(p, a.raw, 0o600); err != nil {
			return nil, err
		}
		files = append(files, p)
	}
	outputPath := filepath.Join(tmpDir, "output.pdf")
	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	if err := pdfapi.AddAttachmentsFile(inputPath, outputPath, files, false, conf); err != nil {
		return nil, fmt.Errorf("evidence: pdfcpu attach: %w", err)
	}
	bundle, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, err
	}

	return &EvidenceResult{
		Bytes:    bundle,
		Manifest: manifest,
		Filename: fmt.Sprintf("hash-evidence-%s.pdf", doc.ID.String()),
	}, nil
}

// ErrNotTerminal is returned when Build is called on a document that
// hasn't reached a terminal state. Drafts + sent + in_progress docs
// can't produce an evidence bundle because there's no final PDF yet.
var ErrNotTerminal = errors.New("evidence: document not in terminal state")

func isTerminal(status string) bool {
	switch status {
	case "completed", "declined", "voided", "expired":
		return true
	}
	return false
}

func pgUUIDOf(u uuid.UUID) pgtypeUUID {
	return pgtypeUUID{Bytes: u, Valid: true}
}

// Tiny re-export of pgtype.UUID so callers don't import pgtype just to
// build the query param. We embed the same byte layout.
type pgtypeUUID = struct {
	Bytes [16]byte
	Valid bool
}

func storageKeyOrEmpty(t struct {
	String string
	Valid  bool
}) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

// stripFinalPDFSuffix returns the storage-key prefix for the document
// directory, so callers can join sibling keys like "audit.payload.txt"
// next to "final.pdf". Expects a key of the form
// "org/<orgID>/documents/<docID>/final.pdf"; falls back to returning the
// input unchanged if the suffix is missing so the caller never crashes.
func stripFinalPDFSuffix(key string) string {
	const suffix = "final.pdf"
	if len(key) >= len(suffix) && key[len(key)-len(suffix):] == suffix {
		return key[:len(key)-len(suffix)]
	}
	return key
}

// firstCertFromPEM returns the first X.509 certificate block in the PEM
// bundle. Returns (nil, nil) if the PEM contains no CERTIFICATE blocks.
func firstCertFromPEM(pemBytes []byte) (*x509.Certificate, error) {
	rest := pemBytes
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return nil, nil
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		rest = remaining
	}
}

// base64Encode is used by the verify path. Exposed at package level so
// the /verify handler can reuse it without duplicating the encoder
// boilerplate. Not strictly needed for Build but kept here for the
// follow-on extract path.
func base64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

var _ = base64Encode
var _ io.Reader = (*bytes.Reader)(nil)
