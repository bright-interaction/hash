// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package evidence implements the cryptographically verifiable evidence bundle.
//
// Builds a single PDF containing:
//
//   - The audit certificate as the visible cover.
//   - final-pdf.pdf as the exact, byte-for-byte signed contract attachment.
//   - Attached files (PDF/A-3-style embeddings) for machine readers:
//   - manifest.json     evidence manifest with hashes + signing key
//   - events.json       exact pre-final document events bound by the cert
//   - versions.json     version history with block-level diffs
//   - manifest-public-key.pem     current export-signing key
//   - certificate-public-key.pem  ceremony certificate's historical key
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
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/versions"
)

// Builder produces evidence bundles. Hold one process-wide.
type Builder struct {
	Q            evidenceQueries
	Storage      blobStore
	Versions     versionStore
	OTSAnchor    OTSAnchor // optional; nil disables anchoring
	PublicKeyPEM string    // pre-formatted ed25519 public key in PEM
	Issuer       string    // human-readable issuer (e.g. "Hash / Bright Interaction AB")
	Signer       evidenceManifestSigner
	// CertificateTrustedPublicKeys contains the current and retained historical
	// raw Ed25519 issuer keys. A stored certificate can predate the key used to
	// sign a newly generated export manifest.
	CertificateTrustedPublicKeys []string
}

// Narrow dependency interfaces make the fail-closed export paths testable.
// The production generated.Queries, storage.Client, and versions.Engine types
// implement them directly.
type evidenceQueries interface {
	ListEventsByDocumentChronological(context.Context, generated.ListEventsByDocumentChronologicalParams) ([]*generated.Event, error)
	ListCompletedQESSessionsForDocument(context.Context, uuid.UUID) ([]*generated.QesSigningSession, error)
}

type blobStore interface {
	GetVerifiedVersion(context.Context, string, string, []byte) ([]byte, error)
	ResolveVerifiedLegacy(context.Context, string, []byte) ([]byte, storage.StoredObject, error)
}

type evidenceManifestSigner interface {
	PublicKeyBase64() string
	PublicKeyPEM() string
	SignEvidenceManifest([]byte) string
}

type versionStore interface {
	History(context.Context, uuid.UUID, int32) ([]*generated.DocumentVersion, error)
	GetByNo(context.Context, uuid.UUID, int32) (*generated.DocumentVersion, error)
}

const (
	maxEvidenceEvents   = 10000
	maxEvidenceVersions = 1000
)

// OTSAnchor is the optional OpenTimestamps client. Default impl lives in
// ots.go; tests can swap a fake.
type OTSAnchor interface {
	Stamp(ctx context.Context, digest []byte) (otsBytes []byte, err error)
}

// Manifest is the top-level JSON every reader cross-references.
type Manifest struct {
	SchemaVersion                 int            `json:"schema_version"`
	GeneratedAt                   string         `json:"generated_at"`
	Issuer                        string         `json:"issuer"`
	DocumentID                    string         `json:"document_id"`
	DocumentName                  string         `json:"document_name"`
	OrgID                         string         `json:"org_id"`
	FinalPDFSHA256                string         `json:"final_pdf_sha256"`
	CompletionEffectiveAt         string         `json:"completion_effective_at,omitempty"`
	AuditCertSHA256               string         `json:"audit_cert_sha256"`
	EventsSHA256                  string         `json:"events_sha256"`
	VersionsSHA256                string         `json:"versions_sha256"`
	ManifestPublicKeyPEMSHA256    string         `json:"manifest_public_key_pem_sha256"`
	ManifestSigningKeySHA256      string         `json:"manifest_signing_key_sha256"`
	CertificatePublicKeyPEMSHA256 string         `json:"certificate_public_key_pem_sha256"`
	CertificateSigningKeySHA256   string         `json:"certificate_signing_key_sha256"`
	ManifestSignature             string         `json:"manifest_signature"`
	ManifestSigDomain             string         `json:"manifest_signature_domain"`
	CertPayloadSHA256             string         `json:"cert_payload_sha256,omitempty"`
	CertSignatureSHA256           string         `json:"cert_signature_sha256,omitempty"`
	SignatureAlgorithm            string         `json:"signature_algorithm,omitempty"`
	SignatureDomain               string         `json:"signature_domain,omitempty"`
	QTSP                          []QTSPBlock    `json:"qtsp,omitempty"`
	Bundle                        BundleSummary  `json:"bundle"`
	OpenTimestamps                *AnchorSummary `json:"open_timestamps,omitempty"`
	Notes                         string         `json:"notes,omitempty"`
}

const (
	LegacyManifestSchemaVersion  = 2
	CurrentManifestSchemaVersion = 3
)

const evidenceManifestSignatureDomain = "hash:evidence-manifest:v1"

// ErrUnboundLegacyQES prevents a new Hash-signed export manifest from
// representing pre-release provider material as a verified qualified
// signature. Those rows did not cryptographically bind and atomically consume
// the provider proof with the exact document ceremony.
var ErrUnboundLegacyQES = errors.New("evidence: legacy QES session material is not bound to the document ceremony and cannot be exported as verified evidence")

// QTSPBlock is retained solely so the verifier can integrity-check historical
// bundle attachments. Its presence proves only what an older Hash manifest
// contained; it does not establish QTSP trust, document-digest binding, a valid
// QES, or legal effect. New bundles never emit this block.
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
// document must be a completed lifecycle root with its own final PDF and
// certificate. Other terminal states do not currently have a signed receipt;
// envelope children share their parent's ceremony and cannot be relabeled as
// independently signed evidence.
func (b *Builder) Build(ctx context.Context, doc *generated.Document) (*EvidenceResult, error) {
	if doc == nil {
		return nil, errors.New("evidence: nil document")
	}
	if doc.Status != "completed" || doc.ParentEnvelopeID.Valid {
		return nil, ErrEvidenceUnavailable
	}
	if !doc.CompletionEffectiveAt.Valid || doc.CompletionEffectiveAt.Time.IsZero() ||
		!doc.CompletedAt.Valid || !doc.CompletedAt.Time.Equal(doc.CompletionEffectiveAt.Time) {
		return nil, errors.New("evidence: completed document has no consistent completion-effective timestamp")
	}
	completionEffectiveAt := doc.CompletionEffectiveAt.Time.UTC().Format(time.RFC3339Nano)
	if !doc.FinalPdfKey.Valid || len(doc.FinalPdfSha) == 0 {
		return nil, fmt.Errorf("evidence: document has no final PDF (status=%s)", doc.Status)
	}
	if b.Storage == nil || b.Q == nil || b.Versions == nil {
		return nil, errors.New("evidence: builder dependencies are not configured")
	}

	// 1. Pull the exact executed contract body. The audit certificate remains
	// separate so it can non-circularly sign this byte digest.
	finalPDF, err := readEvidenceArtifact(ctx, b.Storage, doc, doc.FinalPdfKey.String, doc.FinalPdfSha, doc.FinalPdfVersionID)
	if err != nil {
		return nil, fmt.Errorf("evidence: load final PDF: %w", err)
	}
	finalSHA := sha256.Sum256(finalPDF)
	if !bytes.Equal(finalSHA[:], doc.FinalPdfSha) {
		return nil, fmt.Errorf("%w: final PDF hash does not match the completed document record", ErrArtifactIntegrity)
	}
	if !strictContentAddressedEvidenceArtifactMatches(finalPDF, doc.FinalPdfKey.String, "final", ".pdf") {
		return nil, fmt.Errorf("%w: final PDF does not match its content-addressed storage key", ErrArtifactIntegrity)
	}

	// 2. Pull the separately stored, content-addressed certificate used by the
	// /audit-cert endpoint and as the visible evidence-bundle cover.
	var certPDF []byte
	var certSHA [32]byte
	if doc.AuditCertKey.Valid {
		certDigest := doc.AuditCertSha256
		if len(certDigest) != sha256.Size && !doc.EvidenceVersionPinsRequired {
			certDigest = digestFromContentAddressedArtifactKey(doc.AuditCertKey.String, "audit", ".pdf")
		}
		cert, err := readEvidenceArtifact(ctx, b.Storage, doc, doc.AuditCertKey.String, certDigest, doc.AuditCertVersionID)
		if err != nil {
			return nil, fmt.Errorf("evidence: load declared audit certificate: %w", err)
		}
		if !strictContentAddressedEvidenceArtifactMatches(cert, doc.AuditCertKey.String, "audit", ".pdf") {
			return nil, fmt.Errorf("%w: audit certificate hash does not match its immutable storage key", ErrArtifactIntegrity)
		}
		certPDF = cert
		certSHA = sha256.Sum256(cert)
	}

	// 2b. Pull the exact, independently digest-bound signed payload and detached
	// signature. Drag-drop verification needs these because the cert PDF is a
	// Gotenberg render of the signed HTML, not the signed bytes themselves.
	if !doc.AuditPayloadKey.Valid || len(doc.AuditPayloadSha256) != sha256.Size ||
		!doc.AuditSignatureKey.Valid || len(doc.AuditSignatureSha256) != sha256.Size {
		return nil, errors.New("evidence: completed document is missing content-addressed certificate sidecar commitments")
	}
	certPayload, err := readEvidenceArtifact(ctx, b.Storage, doc, doc.AuditPayloadKey.String, doc.AuditPayloadSha256, doc.AuditPayloadVersionID)
	if err != nil {
		return nil, fmt.Errorf("evidence: load verified certificate payload: %w", err)
	}
	if !strictContentAddressedEvidenceArtifactMatches(certPayload, doc.AuditPayloadKey.String, "audit-payload", ".txt") {
		return nil, fmt.Errorf("%w: certificate payload does not match its content-addressed storage key", ErrArtifactIntegrity)
	}
	certPayloadSHA := sha256.Sum256(certPayload)
	certSignature, err := readEvidenceArtifact(ctx, b.Storage, doc, doc.AuditSignatureKey.String, doc.AuditSignatureSha256, doc.AuditSignatureVersionID)
	if err != nil {
		return nil, fmt.Errorf("evidence: load verified certificate signature: %w", err)
	}
	if !strictContentAddressedEvidenceArtifactMatches(certSignature, doc.AuditSignatureKey.String, "audit-signature", ".txt") {
		return nil, fmt.Errorf("%w: certificate signature does not match its content-addressed storage key", ErrArtifactIntegrity)
	}
	certSignatureSHA := sha256.Sum256(certSignature)
	if len(certPDF) == 0 || len(certPayload) == 0 || len(certSignature) == 0 {
		return nil, errors.New("evidence: completed document is missing its certificate or detached signature evidence")
	}
	commitments, err := ParseCertificateCommitments(certPayload)
	if err != nil {
		return nil, fmt.Errorf("evidence: signed certificate commitments: %w", err)
	}
	if commitments.FinalPDFSHA256 != hex.EncodeToString(finalSHA[:]) {
		return nil, fmt.Errorf("%w: signed certificate does not bind the stored final PDF", ErrArtifactIntegrity)
	}
	manifestSchemaVersion := LegacyManifestSchemaVersion
	manifestCompletionEffectiveAt := ""
	if doc.CompletionEffectiveAtBound {
		if commitments.CompletionEffectiveAt == "" || commitments.CompletionEffectiveAt != completionEffectiveAt {
			return nil, fmt.Errorf("%w: signed certificate completion-effective timestamp does not match the bound document record", ErrArtifactIntegrity)
		}
		manifestSchemaVersion = CurrentManifestSchemaVersion
		manifestCompletionEffectiveAt = completionEffectiveAt
	} else if commitments.CompletionEffectiveAt != "" {
		return nil, fmt.Errorf("%w: legacy-unbound document unexpectedly carries a completion-effective certificate claim", ErrArtifactIntegrity)
	}
	documentNameSHA := sha256.Sum256([]byte(doc.Name))
	if commitments.DocumentID != doc.ID.String() || commitments.OrgID != doc.OrgID.String() ||
		commitments.DocumentNameSHA256 != hex.EncodeToString(documentNameSHA[:]) {
		return nil, fmt.Errorf("%w: signed certificate identity does not match the document record", ErrArtifactIntegrity)
	}

	// 3. Serialize exactly the chronological pre-final event subset committed
	// by the ceremony certificate. Reading the oldest signed count prevents the
	// completion row and later reminders/exports from displacing an older row.
	eventRows, err := b.Q.ListEventsByDocumentChronological(ctx, generated.ListEventsByDocumentChronologicalParams{
		DocumentID: pgUUIDOf(doc.ID),
		Limit:      int32(commitments.DocumentEventsCount),
	})
	if err != nil {
		return nil, fmt.Errorf("evidence: load ceremony events: %w", err)
	}
	if len(eventRows) != commitments.DocumentEventsCount {
		return nil, fmt.Errorf("%w: signed certificate commits to %d document events but %d are available", ErrArtifactIntegrity, commitments.DocumentEventsCount, len(eventRows))
	}
	eventsJSON, eventsCommitment, eventCount, err := BuildCeremonyEventsJSON(doc.ID, eventRows)
	if err != nil {
		return nil, err
	}
	if eventsCommitment != commitments.DocumentEventsSHA256 || eventCount != commitments.DocumentEventsCount {
		return nil, fmt.Errorf("%w: ceremony events do not match the signed certificate commitment", ErrArtifactIntegrity)
	}
	eventsSHA := sha256.Sum256(eventsJSON)

	// 4. Version history with per-step diffs.
	versionRows, err := b.Versions.History(ctx, doc.ID, maxEvidenceVersions+1)
	if err != nil {
		return nil, fmt.Errorf("evidence: load version history: %w", err)
	}
	if len(versionRows) > maxEvidenceVersions {
		return nil, fmt.Errorf("%w: document %s has more than %d versions", ErrEvidenceTooLarge, doc.ID, maxEvidenceVersions)
	}
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
		if cur == nil {
			return nil, errors.New("evidence: version history returned a nil row")
		}
		entry := versionDelta{
			VersionNo:  cur.VersionNo,
			CreatedAt:  cur.CreatedAt.Time.UTC().Format(time.RFC3339),
			CreatedVia: cur.CreatedVia,
			Summary:    cur.Summary,
		}
		if cur.VersionNo > 1 {
			prior, err := b.Versions.GetByNo(ctx, doc.ID, cur.VersionNo-1)
			if err != nil {
				return nil, fmt.Errorf("evidence: load version %d predecessor: %w", cur.VersionNo, err)
			}
			if prior == nil {
				return nil, fmt.Errorf("evidence: version %d predecessor query returned nil", cur.VersionNo)
			}
			changes, err := versions.Diff(prior.BlockTreeJson, cur.BlockTreeJson)
			if err != nil {
				return nil, fmt.Errorf("evidence: diff versions %d and %d: %w", cur.VersionNo-1, cur.VersionNo, err)
			}
			entry.Diff = changes
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

	// 5b. Pre-release QES rows were written before Hash persisted and verified
	// the exact ceremony digest or atomically consumed provider proof with the
	// legal response. A newly signed evidence manifest must never upgrade that
	// raw material into an assertion of QES validity. The separately authorized
	// MCP archive reader remains available for forensic inspection with an
	// explicit unverified-legacy classification.
	qesSessions, qErr := b.Q.ListCompletedQESSessionsForDocument(ctx, doc.ID)
	if qErr != nil {
		return nil, fmt.Errorf("evidence: load completed QES sessions: %w", qErr)
	}
	if len(qesSessions) > 0 {
		return nil, ErrUnboundLegacyQES
	}
	if b.Signer == nil {
		return nil, errors.New("evidence: manifest signer is not configured")
	}
	manifestPubKeyBytes := []byte(b.Signer.PublicKeyPEM())
	if len(manifestPubKeyBytes) == 0 || b.Signer.PublicKeyBase64() == "" {
		return nil, errors.New("evidence: manifest signer has no public key")
	}
	if b.PublicKeyPEM != "" && b.PublicKeyPEM != string(manifestPubKeyBytes) {
		return nil, errors.New("evidence: configured public key does not match manifest signer")
	}
	manifestPubKeySHA := sha256.Sum256(manifestPubKeyBytes)
	manifestKeyFingerprint, err := Ed25519PublicKeyFingerprint(manifestPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("evidence: manifest signing public key: %w", err)
	}
	trustedCertificateKeys := append([]string(nil), b.CertificateTrustedPublicKeys...)
	trustedCertificateKeys = append(trustedCertificateKeys, b.Signer.PublicKeyBase64())
	_, certificatePubKeyBytes, certificateKeyFingerprint, err := resolveCertificateIssuerKey(
		certPayload, certSignature, trustedCertificateKeys,
	)
	if err != nil {
		return nil, err
	}
	certificatePubKeySHA := sha256.Sum256(certificatePubKeyBytes)

	// 6. Manifest before attachments so it can name its own attachment
	// sibling SHAs.
	manifest := Manifest{
		SchemaVersion:                 manifestSchemaVersion,
		GeneratedAt:                   time.Now().UTC().Format(time.RFC3339),
		Issuer:                        b.Issuer,
		DocumentID:                    doc.ID.String(),
		DocumentName:                  doc.Name,
		OrgID:                         doc.OrgID.String(),
		FinalPDFSHA256:                hex.EncodeToString(finalSHA[:]),
		CompletionEffectiveAt:         manifestCompletionEffectiveAt,
		AuditCertSHA256:               hex.EncodeToString(certSHA[:]),
		EventsSHA256:                  hex.EncodeToString(eventsSHA[:]),
		VersionsSHA256:                hex.EncodeToString(versionsSHA[:]),
		ManifestPublicKeyPEMSHA256:    hex.EncodeToString(manifestPubKeySHA[:]),
		ManifestSigningKeySHA256:      manifestKeyFingerprint,
		CertificatePublicKeyPEMSHA256: hex.EncodeToString(certificatePubKeySHA[:]),
		CertificateSigningKeySHA256:   certificateKeyFingerprint,
		ManifestSigDomain:             evidenceManifestSignatureDomain,
		Bundle: BundleSummary{
			FinalPDFKey:  storageKeyOrEmpty(doc.FinalPdfKey),
			AuditCertKey: storageKeyOrEmpty(doc.AuditCertKey),
			EventCount:   eventCount,
			VersionCount: len(deltas),
		},
		Notes: "Evidence bundle for offline forensic review. Any optional development-only OpenTimestamps attachment is not validated by Hash and is not part of the core verification verdict.",
	}
	if len(certPayload) > 0 {
		manifest.CertPayloadSHA256 = hex.EncodeToString(certPayloadSHA[:])
		manifest.SignatureAlgorithm = "ed25519"
		manifest.SignatureDomain = "hash:audit-cert:v1"
	}
	if len(certSignature) > 0 {
		manifest.CertSignatureSHA256 = hex.EncodeToString(certSignatureSHA[:])
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
	canonicalManifest, err := CanonicalManifestForSignature(manifest)
	if err != nil {
		return nil, err
	}
	manifest.ManifestSignature = b.Signer.SignEvidenceManifest(canonicalManifest)
	if manifest.ManifestSignature == "" {
		return nil, errors.New("evidence: manifest signer returned an empty signature")
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
	// The container's visible cover is the certificate. The exact contract is
	// attached once, rather than duplicating a potentially 50+ MiB PDF as both
	// visible pages and an attachment. Verifiers treat final-pdf.pdf as the
	// authoritative artifact named by the signed manifest and certificate claim.
	if err := os.WriteFile(inputPath, certPDF, 0o600); err != nil {
		return nil, err
	}
	attachments := []struct {
		name string
		raw  []byte
	}{
		{"final-pdf.pdf", finalPDF},
		{"manifest.json", manifestJSON},
		{"events.json", eventsJSON},
		{"versions.json", versionsJSON},
		{"manifest-public-key.pem", manifestPubKeyBytes},
		{"certificate-public-key.pem", certificatePubKeyBytes},
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

// ErrEvidenceUnavailable is returned unless the document is a completed
// lifecycle root with its own signed final artifact and certificate.
var ErrEvidenceUnavailable = errors.New("evidence: bundle is only available for a completed lifecycle root")

// ErrNotTerminal remains an alias for callers compiled against the earlier
// API. Its narrowed meaning is intentional: non-completed terminal states do
// not have a signed terminal receipt and must not be marketed as independently verifiable.
var ErrNotTerminal = ErrEvidenceUnavailable

// ErrEvidenceTooLarge is returned instead of silently truncating a verifiable
// export. The caller can increase the documented format limits in a deliberate
// migration; it must never receive a bundle that claims completeness while
// omitting rows.
var ErrEvidenceTooLarge = errors.New("evidence: export exceeds completeness limit")

// ErrArtifactIntegrity marks storage bytes that disagree with the immutable
// digest committed to the completed document row.
var ErrArtifactIntegrity = errors.New("evidence: artifact integrity check failed")

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

func contentAddressedEvidenceArtifactMatches(body []byte, key, prefix, suffix string) bool {
	name := path.Base(key)
	marker := prefix + "-"
	if !strings.HasPrefix(name, marker) || !strings.HasSuffix(name, suffix) {
		return true // historical key; no digest was encoded
	}
	rawHex := strings.TrimSuffix(strings.TrimPrefix(name, marker), suffix)
	if len(rawHex) != sha256.Size*2 {
		return false
	}
	expected, err := hex.DecodeString(rawHex)
	if err != nil {
		return false
	}
	actual := sha256.Sum256(body)
	return bytes.Equal(actual[:], expected)
}

func strictContentAddressedEvidenceArtifactMatches(body []byte, key, prefix, suffix string) bool {
	name := path.Base(key)
	if !strings.HasPrefix(name, prefix+"-") || !strings.HasSuffix(name, suffix) {
		return false
	}
	return contentAddressedEvidenceArtifactMatches(body, key, prefix, suffix)
}

func readEvidenceArtifact(ctx context.Context, store blobStore, doc *generated.Document, key string, digest []byte, versionID pgtype.Text) ([]byte, error) {
	if store == nil || doc == nil || strings.TrimSpace(key) == "" || len(digest) != sha256.Size {
		return nil, errors.New("evidence: artifact commitment is incomplete")
	}
	if versionID.Valid && strings.TrimSpace(versionID.String) != "" {
		return store.GetVerifiedVersion(ctx, key, versionID.String, digest)
	}
	if doc.EvidenceVersionPinsRequired {
		return nil, errors.New("evidence: artifact is missing its required object VersionId")
	}
	body, _, err := store.ResolveVerifiedLegacy(ctx, key, digest)
	return body, err
}

func digestFromContentAddressedArtifactKey(key, prefix, suffix string) []byte {
	name := path.Base(key)
	marker := prefix + "-"
	if !strings.HasPrefix(name, marker) || !strings.HasSuffix(name, suffix) {
		return nil
	}
	raw := strings.TrimSuffix(strings.TrimPrefix(name, marker), suffix)
	if len(raw) != sha256.Size*2 {
		return nil
	}
	digest, err := hex.DecodeString(raw)
	if err != nil || len(digest) != sha256.Size {
		return nil
	}
	return digest
}

// CanonicalManifestForSignature returns the deterministic JSON bytes covered
// by the manifest's detached signature. The signature field itself is cleared
// to avoid a circular input; every other field, including its domain and key
// fingerprint, remains bound.
func CanonicalManifestForSignature(manifest Manifest) ([]byte, error) {
	manifest.ManifestSignature = ""
	return json.Marshal(manifest)
}

// Ed25519PublicKeyFingerprint returns lowercase SHA-256 of the raw 32-byte
// public key carried by one strict SPKI PUBLIC KEY PEM block.
func Ed25519PublicKeyFingerprint(publicKeyPEM []byte) (string, error) {
	block, rest := pem.Decode(publicKeyPEM)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "PUBLIC KEY" {
		return "", errors.New("expected one PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return "", errors.New("public key is not Ed25519")
	}
	digest := sha256.Sum256(pub)
	return hex.EncodeToString(digest[:]), nil
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
var _ evidenceQueries = (*generated.Queries)(nil)
var _ blobStore = (*storage.Client)(nil)
var _ versionStore = (*versions.Engine)(nil)
