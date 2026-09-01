// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package sign owns the document signing state machine and the orchestration
// that turns a recipient's "I sign with this name in this font" click into
// a stamped, hashed final PDF.
package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/netip"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bright-interaction/hash/internal/actiontoken"
	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/i18n"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/storage"
)

// Sentinel errors so handlers can map signing-flow conflicts to the right
// HTTP status instead of a generic 400/500.
var (
	// ErrAlreadySigned is returned when a recipient signs twice (the second
	// POST loses the unique-index race). Handlers should report 409.
	ErrAlreadySigned = errors.New("recipient already signed")
	// ErrDocumentNotSignable is returned when a sign/decline targets a
	// document that is no longer in an active (sent/in_progress) state.
	ErrDocumentNotSignable = errors.New("document is not in a signable state")
	// ErrNotAcknowledgement is returned when Accept targets a signature-required
	// document. Accept only applies to acknowledgement (view/accept) documents.
	ErrNotAcknowledgement = errors.New("document requires a signature, not acceptance")
	// ErrAlreadyAccepted is returned when a recipient accepts twice.
	ErrAlreadyAccepted = errors.New("recipient already accepted")
	// ErrRecipientNotEligibleForChanges is returned when an informational,
	// terminal, or otherwise non-signing recipient attempts negotiation.
	ErrRecipientNotEligibleForChanges = errors.New("recipient is not eligible to request changes")
	// Informational viewer/cc workflows are not implemented end to end. They
	// must never create acceptance evidence or terminate a ceremony through a
	// legacy token.
	ErrRecipientNotEligibleForResponse = errors.New("recipient is not eligible to accept or decline this document")
	// ErrChangeAlreadyResolved is returned when an approve/deny action replays
	// after another request has already resolved the same change request.
	ErrChangeAlreadyResolved = errors.New("change request is already resolved")
	// ErrDocumentNotReadyToFinalize is a fail-closed defense for every finalize
	// caller. Even if a retry-selection query regresses, terminal artifacts are
	// never produced until every required signing role has actually signed.
	ErrDocumentNotReadyToFinalize = errors.New("document still has required recipients awaiting signature")
	// ErrFinalizeInProgress is returned when another worker/request already
	// holds the per-document finalize lock; the caller should treat the
	// signature as captured and let the in-flight finalize complete.
	ErrFinalizeInProgress = errors.New("finalize already in progress for this document")
	// ErrEnvelopeChildFinalization is returned when a retry caller targets an
	// envelope child directly. Children share the root ceremony and terminal
	// artifact, so only the parent may drive their family-wide finalization.
	ErrEnvelopeChildFinalization = errors.New("envelope child finalization is managed by its parent")
	// ErrNotRevisable is returned when a revise targets a document that is not
	// paused in the changes_requested state.
	ErrNotRevisable = errors.New("document is not awaiting revision")
	// ErrRevisionWouldDestroyEvidence fails closed when the current in-place
	// revision model would have to erase a signature, acceptance, or completed
	// field. A future superseding-document model can preserve and link both
	// legal versions; until then the captured evidence remains immutable.
	ErrRevisionWouldDestroyEvidence = errors.New("revision would destroy captured legal evidence")
	// ErrEnvelopeTransitionUnsupported fails closed for reversible negotiation
	// and recipient-decline transitions whose current data model cannot preserve
	// one atomic, coherent state across the wrapper and every frozen child.
	// Envelope signing/completion and sender void remain supported.
	ErrEnvelopeTransitionUnsupported = errors.New("this transition is not supported for envelopes")
	// ErrDocumentNotCommentable is returned when a recipient (signer) comment
	// targets a document that is no longer in an active state. A comment-reply
	// action token has a 14-day TTL and is NOT cleared by
	// InvalidateRecipientTokens, so without this a signer could keep posting
	// comments onto a completed/voided/declined legal record via a stale email
	// link long after the document closed.
	ErrDocumentNotCommentable = errors.New("document is not accepting comments")
	// ErrDocumentRevisedDuringFinalize is returned when finalize's guarded
	// terminal write matches 0 rows: the document left in_progress (a concurrent
	// Revise -> draft or Void -> voided) while the PDF + audit cert were
	// rendering, so completing it would seal signatures that are no longer
	// valid. finalize aborts instead; the document keeps its non-completed
	// state and is re-driven by the normal send/sign flow.
	ErrDocumentRevisedDuringFinalize = errors.New("document left in_progress during finalize; completion aborted")
	// ErrCompletedArtifactUnavailable is returned when a magic token does not
	// belong to a recipient who completed the document, or the document has no
	// completed artifact. It deliberately does not distinguish those cases so a
	// public download route cannot be used to enumerate recipient state.
	ErrCompletedArtifactUnavailable = errors.New("completed artifact is not available for this recipient")
	// ErrSignatureTierUnavailable rejects typed-name signing for any higher
	// assurance tier. AES has no identity-bound proof path, and the current QES
	// session model does not persist/verify/consume a signature over the exact
	// ceremony digest. Calling the SES engine must never downgrade either tier.
	ErrSignatureTierUnavailable = errors.New("requested electronic-signature tier is not available")
	// ErrSignerControllerUnavailable fails closed when the organization that
	// owns a signing document cannot be resolved to a non-empty legal name.
	// The public signer context must never substitute the platform operator for
	// the customer's GDPR controller identity.
	ErrSignerControllerUnavailable = errors.New("signer data controller is unavailable")
	// A database default is not a controller instruction. Legacy ceremonies
	// without an explicit send-time Article 6 confirmation fail closed.
	ErrSignerLawfulBasisUnavailable = errors.New("signer lawful basis is unavailable")
	// ErrInvalidNoticeEvidence rejects malformed evidence and evidence bound to
	// another ceremony identity. The public handler separately reconstructs the
	// current server-authored notice and compares the presented digest exactly;
	// this engine layer preserves that validated snapshot at the mutation seam.
	ErrInvalidNoticeEvidence = errors.New("invalid Article 13 response evidence")
)

// Engine ties together the dependencies the signing flow needs.
type Engine struct {
	// Pool backs the transactional sign/decline/finalize path: row locks
	// (SELECT ... FOR UPDATE) and the per-document finalize advisory lock.
	Pool    *pgxpool.Pool
	Queries *generated.Queries
	Storage EvidenceStorage
	PDF     *render.Gotenberg
	Audit   *audit.Logger
	Mailer  dispatch.Mailer
	Signer  *CertSigner // ed25519 signer for audit certs; nil = signing disabled
	OrgName string
	BaseURL string
	// ActionSecret signs one-click email action links (approve/deny). Derived
	// from the instance signer key; empty disables the email action buttons.
	ActionSecret string

	// BrandingCSS is an optional callback returning the org+document
	// branding as a <style>:root{...}</style> block to inject at the
	// top of the rendered PDF body. Empty string falls through to the
	// default palette. Phase 8.5 wires the branding.Resolver here.
	BrandingCSS func(ctx context.Context, doc *generated.Document) string

	// EnvelopeManifestHTML is an optional callback returning the
	// envelope manifest section to append to the audit cert when the
	// document is an envelope. Empty string for non-envelope docs.
	// Phase 8.6 wires the envelopes.Engine here.
	EnvelopeManifestHTML func(ctx context.Context, doc *generated.Document) string

	// EnvelopeChildren is an optional callback returning the ordered
	// children of an envelope. Phase 8.6.1 wires this to
	// envelopes.Engine.Children so the signer view + sign-completion
	// path can concatenate the children's block trees and propagate
	// terminal state to them on the envelope's behalf.
	EnvelopeChildren func(ctx context.Context, envelope *generated.Document) ([]*generated.Document, error)

	// Now is an injectable clock for the magic-link TTL check + audit
	// timestamps. nil falls through to time.Now().
	Now func() time.Time
}

// EvidenceStorage is the narrow immutable-object capability used by legal
// signing. Keeping it as an interface lets tests prove validation failures do
// not create retained objects.
type EvidenceStorage interface {
	GetVerifiedVersion(context.Context, string, string, []byte) ([]byte, error)
	ResolveVerifiedLegacy(context.Context, string, []byte) ([]byte, storage.StoredObject, error)
	PutEvidenceVersioned(context.Context, string, string, []byte, time.Time) (storage.StoredObject, error)
	RetainEvidenceVersion(context.Context, string, string, []byte, time.Time) error
}

// SignInput is what the signer page POSTs when they finalize.
type SignInput struct {
	TypedName string
	Font      string
	IP        string
	UserAgent string
	Notice    article13.Evidence
}

// Keep the signing API names source-readable while the canonical encoding and
// validation live in the dependency-light article13 package shared by the
// signer handler and the independent evidence verifier.
const Article13NoticeSchema = article13.Schema

type Article13NoticeCopy = article13.Copy
type Article13NoticeEvidence = article13.Evidence

// ParticipantResponseEvidence is the request metadata bound into public
// participant audit events. Notice has already been compared with the digest
// presented for the current server-authored Article 13 notice by the handler.
type ParticipantResponseEvidence struct {
	IP        string
	UserAgent string
	Notice    article13.Evidence
}

func responseAuditPayload(payload map[string]any, notice article13.Evidence) (map[string]any, error) {
	if payload == nil {
		payload = make(map[string]any)
	}
	if err := notice.BindAuditPayload(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func validateNoticeEvidence(rc *RecipientContext, notice article13.Evidence) error {
	if rc == nil || rc.Document == nil || rc.Recipient == nil {
		return ErrInvalidNoticeEvidence
	}
	if err := notice.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidNoticeEvidence, err)
	}
	snapshot := notice.Snapshot
	if snapshot.OrgID != rc.Document.OrgID || snapshot.DocumentID != rc.Document.ID ||
		snapshot.RecipientID != rc.Recipient.ID || !rc.Document.SentAt.Valid ||
		!rc.Document.Article13NoticeEpochAt.Valid ||
		!rc.Document.Article13NoticeEpochAt.Time.Equal(rc.Document.SentAt.Time) ||
		snapshot.Schema != rc.Document.Article13NoticeSchema ||
		snapshot.SentAt != rc.Document.SentAt.Time.UTC().Format(time.RFC3339Nano) {
		return ErrInvalidNoticeEvidence
	}
	return nil
}

// ValidateLockedNoticeEvidence rebinds a previously authenticated Article 13
// acknowledgement to the authoritative document row held by the caller's
// transaction. In particular, sent_at is the ceremony epoch: revise/resend may
// advance it after the magic-link lookup but before the mutation obtains its
// row lock, and evidence from that older epoch must then fail closed.
//
// The function cannot prove that lockedDocument is actually locked; callers
// must pass the row returned by GetDocumentForUpdate (or an equivalent
// transaction-scoped row lock) before performing any side effect.
func ValidateLockedNoticeEvidence(rc *RecipientContext, lockedDocument *generated.Document, notice Article13NoticeEvidence) error {
	if rc == nil || rc.Document == nil || rc.Recipient == nil || lockedDocument == nil ||
		lockedDocument.ID != rc.Document.ID || lockedDocument.OrgID != rc.Document.OrgID {
		return ErrInvalidNoticeEvidence
	}
	lockedContext := &RecipientContext{Document: lockedDocument, Recipient: rc.Recipient}
	return validateNoticeEvidence(lockedContext, notice)
}

// Result returned to the signer page on success.
type Result struct {
	DocumentID  uuid.UUID
	Status      string
	Completed   bool
	FinalPDFKey string
	// FinalPDFURL is the freshly rotated, bounded recipient credential. The
	// ceremony token used for the POST is invalidated atomically on completion
	// and must never be echoed as a final-artifact URL.
	FinalPDFURL string
}

// RecipientContext bundles the verified recipient row with the parent
// document and, for the public signer context, the organization that owns that
// exact document. The handler uses ControllerOrg for the GDPR Article 13
// notice; it must never infer the controller from instance-wide branding.
type RecipientContext struct {
	Recipient               *generated.GetRecipientByTokenHashRow
	Document                *generated.Document
	ControllerOrg           *generated.Org
	LawfulBasisConfirmation *generated.DocumentLawfulBasisConfirmation
}

// ErrMagicLinkExpired is returned by LookupByToken when the recipient's
// magic_token_expires_at or the parent document's expires_at is in the
// past. Handlers surface this as 410 Gone to distinguish a deliberate
// TTL miss from a forged or revoked token (404).
var ErrMagicLinkExpired = errors.New("magic link expired")

const completedArtifactAccessTTL = 24 * time.Hour

// LookupByToken resolves a magic-link token into a verified recipient + the
// parent document. Returns ErrMagicLinkExpired when the per-recipient TTL
// or the doc-level expiry has passed.
func (e *Engine) LookupByToken(ctx context.Context, tokenHash []byte) (*RecipientContext, error) {
	row, err := e.Queries.GetRecipientByTokenHash(ctx, tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("invalid magic link")
	}
	if err != nil {
		return nil, err
	}
	doc, err := e.Queries.GetDocument(ctx, generated.GetDocumentParams{
		ID: row.DocumentID, OrgID: row.DocOrgID,
	})
	if err != nil {
		return nil, fmt.Errorf("load parent document: %w", err)
	}
	if err := checkMagicLinkExpiry(row, doc, e.now()); err != nil {
		return nil, err
	}
	if err := checkActiveCeremonyAccess(doc); err != nil {
		return nil, err
	}
	confirmation, err := e.Queries.GetDocumentLawfulBasisConfirmation(ctx, generated.GetDocumentLawfulBasisConfirmationParams{
		DocumentID: doc.ID,
		OrgID:      doc.OrgID,
	})
	if err != nil || confirmation == nil || !confirmation.ConfirmedAt.Valid ||
		confirmation.DocumentID != doc.ID || confirmation.OrgID != doc.OrgID ||
		strings.TrimSpace(confirmation.LawfulBasis) != strings.TrimSpace(doc.LawfulBasis) ||
		strings.TrimSpace(confirmation.ControllerName) == "" ||
		strings.TrimSpace(confirmation.ControllerContact) == "" ||
		!supportedSignerLawfulBasis(confirmation.LawfulBasis) {
		return nil, ErrSignerLawfulBasisUnavailable
	}
	controllerOrg, err := e.Queries.GetOrg(ctx, doc.OrgID)
	if err != nil {
		return nil, fmt.Errorf("%w: load document organization: %v", ErrSignerControllerUnavailable, err)
	}
	if controllerOrg == nil || controllerOrg.ID != doc.OrgID || strings.TrimSpace(controllerOrg.Name) == "" {
		return nil, ErrSignerControllerUnavailable
	}
	return &RecipientContext{
		Recipient:               row,
		Document:                doc,
		ControllerOrg:           controllerOrg,
		LawfulBasisConfirmation: confirmation,
	}, nil
}

func supportedSignerLawfulBasis(value string) bool {
	return strings.TrimSpace(value) == "contract"
}

// LookupCompletedArtifactByToken authenticates the read-only final-artifact
// route after terminal mutation shutdown. Completion gives recipients who
// actually signed or accepted one bounded 24-hour read window; every ordinary
// signer route remains closed by the document-state gate.
//
// This method must never be used for a mutation or an active document.
func (e *Engine) LookupCompletedArtifactByToken(ctx context.Context, tokenHash []byte) (*RecipientContext, error) {
	row, err := e.Queries.GetRecipientByTokenHash(ctx, tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("invalid magic link")
	}
	if err != nil {
		return nil, err
	}
	doc, err := e.Queries.GetDocument(ctx, generated.GetDocumentParams{
		ID: row.DocumentID, OrgID: row.DocOrgID,
	})
	if err != nil {
		return nil, fmt.Errorf("load parent document: %w", err)
	}
	if err := checkCompletedArtifactAccess(row, doc, e.now()); err != nil {
		return nil, err
	}
	return &RecipientContext{Recipient: row, Document: doc}, nil
}

// checkCompletedArtifactAccess is the deliberately small, time-bounded
// exception for terminal artifact reads. Keeping the policy pure makes it
// difficult for a future handler to grant an expired credential access to an
// active document or to a recipient who never signed/accepted.
func checkCompletedArtifactAccess(row *generated.GetRecipientByTokenHashRow, doc *generated.Document, now time.Time) error {
	if row == nil || doc == nil || doc.Status != "completed" ||
		!doc.FinalPdfKey.Valid || strings.TrimSpace(doc.FinalPdfKey.String) == "" {
		return ErrCompletedArtifactUnavailable
	}
	if row.Status != "signed" && row.Status != "accepted" {
		return ErrCompletedArtifactUnavailable
	}
	if !row.MagicTokenExpiresAt.Valid || row.MagicTokenExpiresAt.Time.IsZero() ||
		!now.Before(row.MagicTokenExpiresAt.Time) {
		return ErrCompletedArtifactUnavailable
	}
	return nil
}

// checkMagicLinkExpiry returns ErrMagicLinkExpired when either the
// per-recipient magic_token_expires_at or the parent documents.expires_at
// is non-null and has passed. Pure function so we can unit-test the TTL
// matrix without a Postgres dependency.
func checkMagicLinkExpiry(row *generated.GetRecipientByTokenHashRow, doc *generated.Document, now time.Time) error {
	if row != nil && row.MagicTokenExpiresAt.Valid && !row.MagicTokenExpiresAt.Time.IsZero() &&
		now.After(row.MagicTokenExpiresAt.Time) {
		return ErrMagicLinkExpired
	}
	if doc != nil && doc.ExpiresAt.Valid && !doc.ExpiresAt.Time.IsZero() && now.After(doc.ExpiresAt.Time) {
		return ErrMagicLinkExpired
	}
	return nil
}

// checkActiveCeremonyAccess is the defense-in-depth state gate shared by all
// ordinary magic-link reads and mutations. Completed-document download uses
// LookupCompletedArtifactByToken instead; draft/terminal documents must never
// be exposed through a stale ceremony credential.
func checkActiveCeremonyAccess(doc *generated.Document) error {
	if doc == nil {
		return ErrDocumentNotSignable
	}
	switch doc.Status {
	case "sent", "in_progress", "changes_requested":
		return nil
	default:
		return ErrDocumentNotSignable
	}
}

// now returns the current time, override via Engine.Now for tests.
func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// LookupByRecipientID resolves a recipient + parent document by id +
// org. Used by the QES callback path which knows the recipient ID
// (carried in the QES session row) but not the magic token. Returns a
// RecipientContext shaped like LookupByToken so the existing Sign +
// Decline paths take the same input regardless of origin.
func (e *Engine) LookupByRecipientID(ctx context.Context, recipientID, orgID uuid.UUID) (*RecipientContext, error) {
	rec, err := e.Queries.GetRecipient(ctx, generated.GetRecipientParams{ID: recipientID, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("recipient not found")
	}
	if err != nil {
		return nil, err
	}
	doc, err := e.Queries.GetDocument(ctx, generated.GetDocumentParams{
		ID: rec.DocumentID, OrgID: orgID,
	})
	if err != nil {
		return nil, fmt.Errorf("load parent document: %w", err)
	}
	if err := checkActiveCeremonyAccess(doc); err != nil {
		return nil, err
	}
	row := &generated.GetRecipientByTokenHashRow{
		ID:             rec.ID,
		DocumentID:     rec.DocumentID,
		Role:           rec.Role,
		Email:          rec.Email,
		Name:           rec.Name,
		OrderIndex:     rec.OrderIndex,
		Status:         rec.Status,
		Locale:         rec.Locale,
		MagicTokenHash: rec.MagicTokenHash,
		SentAt:         rec.SentAt,
		FirstViewedAt:  rec.FirstViewedAt,
		SignedAt:       rec.SignedAt,
		DeclinedReason: rec.DeclinedReason,
		CreatedAt:      rec.CreatedAt,
		DocOrgID:       orgID,
		DocStatus:      doc.Status,
	}
	return &RecipientContext{Recipient: row, Document: doc}, nil
}

// Sign processes a verified sign action: render the signature, advance the
// recipient + document status, and finalize the PDF if the document is now
// fully signed.
//
// The whole mutation runs inside one transaction holding a row lock on the
// document (SELECT ... FOR UPDATE), so concurrent signs on the same document
// serialize. That, the unique index on signatures(document_id, recipient_id),
// and the status-precondition UPDATEs together close the double-POST and
// double-finalize races: a duplicate signature is a no-op, and exactly one
// signer observes "no unsigned signers remaining" and finalizes. The slow
// Gotenberg/MinIO finalize runs AFTER the lock is released (the last
// signature is already durably committed) and is itself guarded by a
// per-document advisory lock + idempotency check.
func (e *Engine) Sign(ctx context.Context, rc *RecipientContext, in SignInput) (*Result, error) {
	if !render.IsValidFont(in.Font) {
		return nil, fmt.Errorf("unsupported signature font %q", in.Font)
	}
	if err := render.ValidateSignatureName(in.TypedName); err != nil {
		return nil, err
	}
	if rc == nil || rc.Document == nil || rc.Recipient == nil {
		return nil, ErrInvalidNoticeEvidence
	}
	doc := rc.Document
	rec := rc.Recipient
	if err := requireSESTypedSignature(doc); err != nil {
		return nil, err
	}
	if err := validateNoticeEvidence(rc, in.Notice); err != nil {
		return nil, err
	}
	requiredRoles, err := e.signerRolesForDocument(ctx, doc)
	if err != nil {
		return nil, err
	}

	// Render the signature span and resolve its field, but do not retain any
	// object yet. Authoritative state/recipient/required-field checks happen
	// under the document lock before immutable storage is touched.
	prep, err := e.prepareSignature(ctx, doc, rec, in)
	if err != nil {
		return nil, err
	}

	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)

	// Lock the document and re-read the authoritative status under the lock.
	lockedDoc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, fmt.Errorf("lock document: %w", err)
	}
	if err := ValidateLockedNoticeEvidence(rc, lockedDoc, in.Notice); err != nil {
		return nil, err
	}
	if lockedDoc.Status != "sent" && lockedDoc.Status != "in_progress" {
		return nil, ErrDocumentNotSignable
	}
	if err := requireSESTypedSignature(lockedDoc); err != nil {
		return nil, err
	}
	freshRec, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: rec.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, err
	}
	if freshRec.DocumentID != doc.ID || !recipients.CanRespond(freshRec.Role) {
		return nil, ErrRecipientNotEligibleForResponse
	}
	if freshRec.Status == "signed" {
		return nil, ErrAlreadySigned
	}
	if freshRec.Status == "declined" {
		return nil, errors.New("recipient already declined")
	}

	// v1.2: refuse to sign if any required non-signature field for this
	// recipient is still unfilled. The signer page should POST /fields first;
	// this gate exists so a malicious client can't skip the field-submit step
	// by calling /sign directly.
	unfilled, ferr := q.CountUnfilledRequiredForRecipient(ctx, generated.CountUnfilledRequiredForRecipientParams{
		DocumentID:  doc.ID,
		RecipientID: pgtype.UUID{Bytes: rec.ID, Valid: true},
	})
	if ferr != nil {
		return nil, fmt.Errorf("check required signer fields: %w", ferr)
	}
	if unfilled > 0 {
		return nil, fmt.Errorf("%d required field(s) unfilled", unfilled)
	}

	fieldRow, err := e.findOrInsertFieldTx(ctx, q, lockedDoc, rec.ID, prep.fieldBlockID)
	if err != nil {
		return nil, err
	}
	if err := e.storePreparedSignature(ctx, lockedDoc, rec.ID, prep); err != nil {
		return nil, err
	}
	sig, err := e.insertSignatureRow(ctx, q, lockedDoc, rec.ID, fieldRow, prep, in)
	if err != nil {
		return nil, err
	}

	if err := q.SetRecipientStatus(ctx, generated.SetRecipientStatusParams{
		ID: rec.ID, DocumentID: doc.ID,
		Status: "signed", DeclinedReason: pgtype.Text{},
	}); err != nil {
		return nil, fmt.Errorf("set recipient signed: %w", err)
	}

	if lockedDoc.Status == "sent" {
		if _, err := q.SetDocumentStatus(ctx, generated.SetDocumentStatusParams{
			ID: doc.ID, OrgID: doc.OrgID, Status: "in_progress",
		}); err != nil {
			return nil, fmt.Errorf("transition to in_progress: %w", err)
		}
	}

	remaining, err := q.CountUnsignedSignersByRoles(ctx, generated.CountUnsignedSignersByRolesParams{
		DocumentID: doc.ID,
		Roles:      requiredRoles,
	})
	if err != nil {
		return nil, err
	}
	signedPayload, err := responseAuditPayload(map[string]any{
		"font":         in.Font,
		"typed_name":   in.TypedName,
		"image_sha256": fmt.Sprintf("%x", sig.ImageSha256),
		"signature_id": sig.ID,
	}, in.Notice)
	if err != nil {
		return nil, fmt.Errorf("bind signature notice evidence: %w", err)
	}
	signedEvent := audit.Entry{
		OrgID: doc.OrgID, DocumentID: &doc.ID, RecipientID: &rec.ID,
		Kind:      audit.KindDocumentSigned,
		IP:        in.IP,
		UserAgent: in.UserAgent,
		Payload:   signedPayload,
	}
	pendingAudit, err := e.Audit.LogTx(ctx, tx, signedEvent)
	if err != nil {
		return nil, fmt.Errorf("audit signature: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit signature: %w", err)
	}
	e.Audit.Publish(pendingAudit)

	if remaining > 0 {
		return &Result{DocumentID: doc.ID, Status: "in_progress", Completed: false}, nil
	}

	// Last signer: finalize. The signature is already committed, so a finalize
	// failure no longer strands the document - the finalize-retry worker picks
	// it up. We therefore report "signed, finalizing" rather than failing the
	// signer's request.
	completionCredential := &completionCredentialCapture{recipientID: rec.ID}
	finalKey, _, _, ferr := e.finalize(ctx, doc.OrgID, doc.ID, completionCredential)
	if ferr != nil {
		// ErrFinalizeInProgress (another finalize holds the lock) and
		// ErrDocumentRevisedDuringFinalize (revised/voided under us) are
		// expected concurrency outcomes, not sign errors: the signature is
		// captured and the document stays non-completed.
		if !errors.Is(ferr, ErrFinalizeInProgress) && !errors.Is(ferr, ErrDocumentRevisedDuringFinalize) {
			// Operational failures must not append another document event after
			// finalizing has captured the certificate event set. The durable
			// finalization intent/last_error is the retry record; structured logs
			// carry diagnostic detail without invalidating that commitment.
			slog.Error("document finalization failed after signature commit",
				"document_id", doc.ID, "org_id", doc.OrgID, "err", ferr)
		}
		return &Result{DocumentID: doc.ID, Status: "in_progress", Completed: false}, nil
	}
	return &Result{
		DocumentID: doc.ID, Status: "completed", Completed: true, FinalPDFKey: finalKey,
		FinalPDFURL: completedArtifactPath(completionCredential.rawToken),
	}, nil
}

func requireSESTypedSignature(doc *generated.Document) error {
	if doc == nil || !strings.EqualFold(strings.TrimSpace(doc.RoutingTier), "SES") {
		return ErrSignatureTierUnavailable
	}
	return nil
}

// Accept records a recipient's acknowledgement of a NO-SIGNATURE document
// (requires_signature = false). It is the acknowledgement-mode twin of Sign:
// no signature image is created, but completion still emits an Ed25519 audit
// certificate binding the accepted final PDF and pre-final audit-chain head.
// When every acceptor has accepted, the retained upload is copied to a
// digest-addressed final artifact and sealed through the acknowledgement path.
func (e *Engine) Accept(ctx context.Context, rc *RecipientContext, evidence ParticipantResponseEvidence) (*Result, error) {
	if err := validateNoticeEvidence(rc, evidence.Notice); err != nil {
		return nil, err
	}
	doc := rc.Document
	rec := rc.Recipient

	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)

	lockedDoc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, fmt.Errorf("lock document: %w", err)
	}
	if err := ValidateLockedNoticeEvidence(rc, lockedDoc, evidence.Notice); err != nil {
		return nil, err
	}
	if lockedDoc.RequiresSignature {
		return nil, ErrNotAcknowledgement
	}
	if err := requireSESTypedSignature(lockedDoc); err != nil {
		return nil, err
	}
	if lockedDoc.Status != "sent" && lockedDoc.Status != "in_progress" {
		return nil, ErrDocumentNotSignable
	}
	freshRec, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: rec.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, err
	}
	if freshRec.DocumentID != doc.ID || !recipients.CanRespond(freshRec.Role) {
		return nil, ErrRecipientNotEligibleForResponse
	}
	if freshRec.Status == "accepted" {
		return nil, ErrAlreadyAccepted
	}
	if freshRec.Status == "declined" {
		return nil, errors.New("recipient already declined")
	}

	if err := q.SetRecipientStatus(ctx, generated.SetRecipientStatusParams{
		ID: rec.ID, DocumentID: doc.ID,
		Status: "accepted", DeclinedReason: pgtype.Text{},
	}); err != nil {
		return nil, fmt.Errorf("set recipient accepted: %w", err)
	}
	if lockedDoc.Status == "sent" {
		if _, err := q.SetDocumentStatus(ctx, generated.SetDocumentStatusParams{
			ID: doc.ID, OrgID: doc.OrgID, Status: "in_progress",
		}); err != nil {
			return nil, fmt.Errorf("transition to in_progress: %w", err)
		}
	}
	remaining, err := q.CountPendingAcceptors(ctx, doc.ID)
	if err != nil {
		return nil, err
	}
	acceptedPayload, err := responseAuditPayload(map[string]any{
		"recipient_email": rec.Email,
	}, evidence.Notice)
	if err != nil {
		return nil, fmt.Errorf("bind acceptance notice evidence: %w", err)
	}
	acceptedEvent := audit.Entry{
		OrgID: doc.OrgID, DocumentID: &doc.ID, RecipientID: &rec.ID,
		Kind:      audit.KindDocumentAccepted,
		IP:        evidence.IP,
		UserAgent: evidence.UserAgent,
		Payload:   acceptedPayload,
	}
	pendingAudit, err := e.Audit.LogTx(ctx, tx, acceptedEvent)
	if err != nil {
		return nil, fmt.Errorf("audit acceptance: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit accept: %w", err)
	}
	e.Audit.Publish(pendingAudit)

	if remaining > 0 {
		return &Result{DocumentID: doc.ID, Status: "in_progress", Completed: false}, nil
	}

	// Every acceptor has accepted: seal the acknowledged PDF. Completion,
	// bounded download credentials, notification outbox, reminder cancellation,
	// and audit event commit together; transient render/storage failure leaves
	// the doc in_progress for the finalize-retry worker.
	completionCredential := &completionCredentialCapture{recipientID: rec.ID}
	completedDoc, did, cerr := e.completeAcknowledgedDocument(ctx, doc.OrgID, doc.ID, completionCredential)
	if cerr != nil || !did {
		return &Result{DocumentID: doc.ID, Status: "in_progress", Completed: false}, nil
	}
	finalKey := acknowledgedFinalKey(completedDoc)
	return &Result{
		DocumentID: doc.ID, Status: "completed", Completed: true, FinalPDFKey: finalKey,
		FinalPDFURL: completedArtifactPath(completionCredential.rawToken),
	}, nil
}

// completeAcknowledgedDocument seals an acknowledgement with the same
// non-circular signed evidence model as a signature ceremony. The retained
// source becomes a digest-addressed final PDF, and a separate Ed25519 audit
// certificate binds that exact digest plus the pre-final audit-chain head.
func (e *Engine) completeAcknowledgedDocument(ctx context.Context, orgID, docID uuid.UUID, capture *completionCredentialCapture) (*generated.Document, bool, error) {
	conn, err := e.Pool.Acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	defer conn.Release()
	lockKey := advisoryLockKey(docID)
	var got bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lockKey).Scan(&got); err != nil { //nolint:rawsql
		return nil, false, err
	}
	if !got {
		return nil, false, ErrFinalizeInProgress
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", lockKey) }() //nolint:rawsql

	prepared, err := e.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: docID, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if prepared.Status == "completed" && prepared.FinalPdfKey.Valid && prepared.AuditCertKey.Valid {
		return prepared, false, nil
	}
	if prepared.Status == "finalizing" && !prepared.RequiresSignature {
		if _, ierr := e.Queries.GetDocumentFinalizationIntent(ctx, generated.GetDocumentFinalizationIntentParams{
			DocumentID: prepared.ID, OrgID: prepared.OrgID,
		}); ierr == nil {
			return e.resumeDocumentFinalization(ctx, conn, prepared, capture)
		} else if !errors.Is(ierr, pgx.ErrNoRows) {
			return nil, false, fmt.Errorf("load acknowledgement finalization intent: %w", ierr)
		}
		// A crash can happen after the durable in_progress -> finalizing claim
		// but before the staged-object intent is inserted. Rebuild the exact
		// artifacts below; content-addressed keys make this retry idempotent.
	}
	if prepared.Status != "in_progress" && prepared.Status != "finalizing" {
		return nil, false, nil
	}
	if prepared.RequiresSignature {
		return nil, false, nil
	}
	if prepared.Status == "in_progress" {
		prepared, err = e.claimDocumentFinalizing(ctx, conn, prepared.OrgID, prepared.ID, "acknowledgement")
		if err != nil {
			return nil, false, err
		}
	}
	prepared, err = e.ensureDocumentSourceVersions(ctx, prepared)
	if err != nil {
		return nil, false, err
	}
	retainUntil, err := finalizationRetentionDeadline(prepared)
	if err != nil {
		return nil, false, fmt.Errorf("finalize acknowledgement: %w", err)
	}

	// The document is now durably non-interactive. No accept/decline/change,
	// reminder, view, or field event can enter the certificate's pre-final
	// document-event set while the slow storage/render work runs.
	pdfBytes, err := e.loadSourcePDF(ctx, prepared)
	if err != nil {
		return nil, false, fmt.Errorf("load acknowledgement source: %w", err)
	}
	finalSum := sha256.Sum256(pdfBytes)
	artifactDir := path.Join("org", prepared.OrgID.String(), "documents", prepared.ID.String())
	finalKey := path.Join(artifactDir, "final-"+hex.EncodeToString(finalSum[:])+".pdf")
	storedFinal, err := e.Storage.PutEvidenceVersioned(ctx, finalKey, "application/pdf", pdfBytes, retainUntil)
	if err != nil {
		return nil, false, fmt.Errorf("store acknowledgement final PDF: %w", err)
	}
	if storedFinal.SHA256 != finalSum || strings.TrimSpace(storedFinal.VersionID) == "" {
		return nil, false, errors.New("store acknowledgement final PDF: storage digest mismatch")
	}
	chainHead, err := e.Queries.LatestEventChainHeadForOrg(ctx, prepared.OrgID)
	if err != nil {
		return nil, false, fmt.Errorf("load acknowledgement pre-final audit chain head: %w", err)
	}
	documentEvents, err := e.loadCertificateDocumentEvents(ctx, prepared.ID)
	if err != nil {
		return nil, false, err
	}
	claims, err := newCertificateEvidenceClaims(prepared, finalSum[:], chainHead, documentEvents)
	if err != nil {
		return nil, false, err
	}
	brandCSS := ""
	if e.BrandingCSS != nil {
		brandCSS = e.BrandingCSS(ctx, prepared)
	}
	certArtifacts, err := e.renderAndStoreAuditCertificate(ctx, prepared, nil, claims, artifactDir, brandCSS, retainUntil)
	if err != nil {
		return nil, false, fmt.Errorf("stage acknowledgement audit certificate: %w", err)
	}
	staged := stagedDocumentFinalization{
		Mode: "acknowledgement", FinalKey: finalKey, FinalSHA256: finalSum,
		FinalVersionID: storedFinal.VersionID, Certificate: certArtifacts,
	}
	if err := e.beginDocumentFinalization(ctx, conn, prepared, staged); err != nil {
		return nil, false, err
	}
	prepared.Status = "finalizing"
	return e.resumeDocumentFinalization(ctx, conn, prepared, capture)
}

func acknowledgedFinalKey(doc *generated.Document) string {
	if doc != nil && doc.FinalPdfKey.Valid {
		return doc.FinalPdfKey.String
	}
	return ""
}

func completedArtifactPath(rawToken string) string {
	if strings.TrimSpace(rawToken) == "" {
		return ""
	}
	return "/sign/" + rawToken + "/final-pdf"
}

// FinalizeStranded re-runs finalize for a document whose signers all signed
// but whose finalize failed (Gotenberg/MinIO outage). Invoked by the
// finalize-retry worker loop. Idempotent: a no-op if the document is already
// finalized or another finalize is in flight.
func (e *Engine) FinalizeStranded(ctx context.Context, orgID, docID uuid.UUID) error {
	doc, err := e.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: docID, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if doc.ParentEnvelopeID.Valid {
		return ErrEnvelopeChildFinalization
	}
	if (doc.Status != "in_progress" && doc.Status != "finalizing") || doc.FinalPdfKey.Valid {
		return nil
	}
	// A finalizing row already passed the locked readiness claim. Route it
	// straight through the mode-specific resume/rebuild path even when the
	// process died before it could persist an artifact intent.
	if doc.Status == "finalizing" {
		if doc.RequiresSignature {
			_, _, _, err := e.finalize(ctx, orgID, docID, nil)
			if errors.Is(err, ErrFinalizeInProgress) {
				return nil
			}
			return err
		}
		_, _, err := e.completeAcknowledgedDocument(ctx, orgID, docID, nil)
		if errors.Is(err, ErrFinalizeInProgress) {
			return nil
		}
		return err
	}
	recipients, err := e.Queries.ListRecipientsByDocument(ctx, docID)
	if err != nil {
		return err
	}
	if !doc.RequiresSignature {
		if !allRequiredAcceptorsAccepted(recipients) {
			return nil
		}
		_, _, err := e.completeAcknowledgedDocument(ctx, orgID, docID, nil)
		if err != nil {
			return err
		}
		return nil
	}
	requiredRoles, err := e.signerRolesForDocument(ctx, doc)
	if err != nil {
		return err
	}
	if !allRequiredRecipientsSignedForRoles(requiredRoles, recipients) {
		return nil
	}

	_, _, did, err := e.finalize(ctx, orgID, docID, nil)
	if errors.Is(err, ErrFinalizeInProgress) {
		return nil
	}
	if err != nil {
		return err
	}
	if !did {
		return nil
	}
	return nil
}

// completionTxStore is deliberately satisfied by a transaction-scoped sqlc
// Queries handle. QueueingMailer completion rows must use this handle rather
// than the mailer's pool-scoped Queries, otherwise the document could commit
// while its notification enqueue is lost (or vice versa).
type completionTxStore interface {
	ListRecipientsByDocument(context.Context, uuid.UUID) ([]*generated.Recipient, error)
	RotateCompletedArtifactToken(context.Context, generated.RotateCompletedArtifactTokenParams) (int64, error)
	GetUser(context.Context, uuid.UUID) (*generated.User, error)
	emailDeliveryEnqueuer
}

type emailDeliveryEnqueuer interface {
	EnqueueEmailDelivery(context.Context, generated.EnqueueEmailDeliveryParams) (*generated.EmailDelivery, error)
}

type completedRecipientCredential struct {
	rec       *generated.Recipient
	rawToken  string
	expiresAt time.Time
}

type completionCredentialCapture struct {
	recipientID uuid.UUID
	rawToken    string
}

// prepareCompletionNotificationsTx rotates every eligible recipient away from
// the ceremony token, renders its recipient-scoped download link, and (for the
// production QueueingMailer) writes every message to the durable outbox. The
// caller invokes this before the terminal transaction commits, so any token,
// rendering, sender lookup, or enqueue failure rolls the completion back.
func (e *Engine) prepareCompletionNotificationsTx(ctx context.Context, q completionTxStore, doc *generated.Document, requiredRoles map[string]struct{}, capture *completionCredentialCapture) ([]dispatch.Message, error) {
	if q == nil || doc == nil || doc.Status != "completed" {
		return nil, errors.New("completion notifications require a completed document and transaction store")
	}
	recipients, err := q.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil {
		return nil, fmt.Errorf("list completion recipients: %w", err)
	}
	credentials, err := e.rotateCompletedArtifactCredentials(ctx, q, doc, recipients, requiredRoles)
	if err != nil {
		return nil, err
	}
	if capture != nil {
		for _, credential := range credentials {
			if credential.rec != nil && credential.rec.ID == capture.recipientID {
				capture.rawToken = credential.rawToken
				break
			}
		}
		if strings.TrimSpace(capture.rawToken) == "" {
			return nil, fmt.Errorf("completed recipient %s did not receive an artifact credential", capture.recipientID)
		}
	}
	if e.Mailer == nil {
		return nil, nil
	}
	sender, err := q.GetUser(ctx, doc.SenderID)
	if err != nil {
		return nil, fmt.Errorf("load completion sender: %w", err)
	}
	messages, err := e.renderCompletionMessages(doc, sender, credentials)
	if err != nil {
		return nil, err
	}
	if usesDurableEmailQueue(e.Mailer) {
		if err := enqueueNotificationEmailsTx(ctx, q, messages); err != nil {
			return nil, fmt.Errorf("persist completion outbox: %w", err)
		}
	}
	return messages, nil
}

func (e *Engine) rotateCompletedArtifactCredentials(ctx context.Context, q completionTxStore, doc *generated.Document, recipients []*generated.Recipient, requiredRoles map[string]struct{}) ([]completedRecipientCredential, error) {
	expiresAt := pgtype.Timestamptz{Time: e.now().Add(completedArtifactAccessTTL), Valid: true}
	credentials := make([]completedRecipientCredential, 0, len(recipients))
	for _, rec := range recipients {
		if !recipientReceivesCompletedArtifact(doc, rec, requiredRoles) {
			continue
		}
		rawToken, tokenHash, err := auth.MintMagicToken()
		if err != nil {
			return nil, fmt.Errorf("mint completed artifact token: %w", err)
		}
		rows, err := q.RotateCompletedArtifactToken(ctx, generated.RotateCompletedArtifactTokenParams{
			ID:                  rec.ID,
			DocumentID:          doc.ID,
			MagicTokenHash:      tokenHash,
			MagicTokenExpiresAt: expiresAt,
		})
		if err != nil {
			return nil, fmt.Errorf("rotate completed artifact token for recipient %s: %w", rec.ID, err)
		}
		if rows != 1 {
			return nil, fmt.Errorf("rotate completed artifact token for recipient %s: updated %d rows", rec.ID, rows)
		}
		credentials = append(credentials, completedRecipientCredential{rec: rec, rawToken: rawToken, expiresAt: expiresAt.Time.UTC()})
	}
	return credentials, nil
}

func recipientReceivesCompletedArtifact(doc *generated.Document, rec *generated.Recipient, requiredRoles map[string]struct{}) bool {
	if doc == nil || rec == nil {
		return false
	}
	if !doc.RequiresSignature {
		return rec.Role != "cc" && rec.Status == "accepted"
	}
	if rec.Status != "signed" {
		return false
	}
	_, required := requiredRoles[rec.Role]
	return required
}

// receivesCompletionEmail retains the signature-role policy helper used by
// existing callers/tests. Acknowledgement recipients use the document-aware
// recipientReceivesCompletedArtifact path above.
func receivesCompletionEmail(rec *generated.Recipient, requiredRoles map[string]struct{}) bool {
	return recipientReceivesCompletedArtifact(&generated.Document{RequiresSignature: true}, rec, requiredRoles)
}

func (e *Engine) renderCompletionMessages(doc *generated.Document, sender *generated.User, credentials []completedRecipientCredential) ([]dispatch.Message, error) {
	if doc == nil || sender == nil {
		return nil, errors.New("render completion emails: document and sender are required")
	}
	baseURL := strings.TrimRight(e.BaseURL, "/")
	messages := make([]dispatch.Message, 0, len(credentials)+1)
	for _, credential := range credentials {
		if credential.rec == nil || strings.TrimSpace(credential.rawToken) == "" {
			return nil, errors.New("render completion emails: recipient credential is incomplete")
		}
		message, err := renderNotificationEmail(dispatch.KindCompletedSigner, credential.rec.Email, dispatch.TemplateContext{
			DocumentName:      doc.Name,
			SenderName:        sender.Name,
			SenderEmail:       sender.Email,
			RecipientName:     credential.rec.Name,
			OrgName:           e.OrgName,
			Locale:            credential.rec.Locale,
			DownloadURL:       baseURL + "/sign/" + credential.rawToken + "/final-pdf",
			DownloadExpiresAt: credential.expiresAt.UTC().Format(time.RFC3339),
			Acknowledgement:   !doc.RequiresSignature,
		})
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	senderURL := baseURL + "/api/v1/documents/" + doc.ID.String() + "/final-pdf"
	senderMessage, err := renderNotificationEmail(dispatch.KindCompletedSender, sender.Email, dispatch.TemplateContext{
		DocumentName:    doc.Name,
		SenderName:      sender.Name,
		SenderEmail:     sender.Email,
		RecipientName:   sender.Name,
		OrgName:         e.OrgName,
		DownloadURL:     senderURL,
		Acknowledgement: !doc.RequiresSignature,
	})
	if err != nil {
		return nil, err
	}
	return append(messages, senderMessage), nil
}

func renderNotificationEmail(kind, to string, templateContext dispatch.TemplateContext) (dispatch.Message, error) {
	subject, htmlBody, textBody, err := dispatch.Render(kind, templateContext)
	if err != nil {
		return dispatch.Message{}, fmt.Errorf("render %s: %w", kind, err)
	}
	return dispatch.Message{
		To: to, Subject: subject, HTML: htmlBody, Text: textBody,
		ReplyTo: templateContext.SenderEmail, FromName: templateContext.OrgName,
	}, nil
}

// prepareNotificationTx is the shared render/outbox boundary for lifecycle
// notifications. Production QueueingMailer messages are persisted through the
// caller's transaction-scoped query handle; non-queue adapters receive the
// already-rendered message synchronously after commit via deliverPostCommitEmails.
func (e *Engine) prepareNotificationTx(ctx context.Context, q emailDeliveryEnqueuer, kind, to string, templateContext dispatch.TemplateContext) ([]dispatch.Message, error) {
	if e.Mailer == nil {
		return nil, nil
	}
	message, err := renderNotificationEmail(kind, to, templateContext)
	if err != nil {
		return nil, err
	}
	messages := []dispatch.Message{message}
	if usesDurableEmailQueue(e.Mailer) {
		if err := enqueueNotificationEmailsTx(ctx, q, messages); err != nil {
			return nil, err
		}
	}
	return messages, nil
}

func usesDurableEmailQueue(mailer dispatch.Mailer) bool {
	switch mailer.(type) {
	case dispatch.QueueingMailer, *dispatch.QueueingMailer:
		return true
	default:
		return false
	}
}

func enqueueNotificationEmailsTx(ctx context.Context, q emailDeliveryEnqueuer, messages []dispatch.Message) error {
	if q == nil {
		return errors.New("email outbox is unavailable")
	}
	for _, message := range messages {
		headers := json.RawMessage("{}")
		if len(message.Headers) > 0 {
			encoded, err := json.Marshal(message.Headers)
			if err != nil {
				return fmt.Errorf("encode notification email headers: %w", err)
			}
			headers = encoded
		}
		delivery, err := q.EnqueueEmailDelivery(ctx, generated.EnqueueEmailDeliveryParams{
			ToEmail: message.To, Subject: message.Subject, HtmlBody: message.HTML, TextBody: message.Text,
			ReplyTo: message.ReplyTo, FromName: message.FromName, HeadersJson: headers,
		})
		if err != nil {
			return fmt.Errorf("enqueue notification email to %s: %w", dispatch.MaskEmail(message.To), err)
		}
		if delivery == nil {
			return fmt.Errorf("enqueue notification email to %s returned no delivery", dispatch.MaskEmail(message.To))
		}
	}
	return nil
}

// Non-queue mailers exist for local tests and adapters only. They are invoked
// synchronously after commit, with no goroutine that could hide a DB-backed
// QueueingMailer enqueue failure after the terminal state is durable.
func (e *Engine) deliverPostCommitEmails(messages []dispatch.Message) {
	if e.Mailer == nil || usesDurableEmailQueue(e.Mailer) {
		return
	}
	for _, message := range messages {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := e.Mailer.Send(ctx, message)
		cancel()
		if err != nil {
			slog.Error("post-commit notification delivery failed",
				"recipient", dispatch.MaskEmail(message.To), "err", dispatch.ScrubEmails(err.Error()))
		}
	}
}

// Decline marks a recipient as declined; the document moves to declined too.
//
// Gated against terminal documents: a recipient with a still-live magic link
// can no longer flip a completed/voided/declined/expired contract to declined,
// and an already-signed recipient cannot self-downgrade. Runs in a tx holding
// the document row lock so it can't race finalize, and invalidates every magic
// link for the document on the terminal transition.
func completedResponseError(status string) error {
	switch status {
	case "signed":
		return ErrAlreadySigned
	case "accepted":
		return ErrAlreadyAccepted
	default:
		return nil
	}
}

func (e *Engine) Decline(ctx context.Context, rc *RecipientContext, reason string, evidence ParticipantResponseEvidence) error {
	if err := validateNoticeEvidence(rc, evidence.Notice); err != nil {
		return err
	}
	rec := rc.Recipient
	doc := rc.Document

	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)

	lockedDoc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return fmt.Errorf("lock document: %w", err)
	}
	if err := ValidateLockedNoticeEvidence(rc, lockedDoc, evidence.Notice); err != nil {
		return err
	}
	if lockedDoc.Status != "sent" && lockedDoc.Status != "in_progress" {
		return ErrDocumentNotSignable
	}
	if err := rejectUnsupportedEnvelopeTransition(lockedDoc, "decline"); err != nil {
		return err
	}
	freshRec, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: rec.ID, OrgID: doc.OrgID})
	if err != nil {
		return err
	}
	if freshRec.DocumentID != doc.ID || !recipients.CanRespond(freshRec.Role) {
		return ErrRecipientNotEligibleForResponse
	}
	if freshRec.Status == "declined" {
		return nil // idempotent
	}
	if err := completedResponseError(freshRec.Status); err != nil {
		return err
	}

	if err := q.SetRecipientStatus(ctx, generated.SetRecipientStatusParams{
		ID: rec.ID, DocumentID: rec.DocumentID,
		Status:         "declined",
		DeclinedReason: pgtype.Text{String: reason, Valid: reason != ""},
	}); err != nil {
		return err
	}
	if _, err := q.DeclineDocumentIfActive(ctx, generated.DeclineDocumentIfActiveParams{
		ID: doc.ID, OrgID: doc.OrgID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDocumentNotSignable
		}
		return err
	}
	if err := q.InvalidateRecipientTokens(ctx, doc.ID); err != nil {
		return err
	}
	var notificationMessages []dispatch.Message
	if e.Mailer != nil {
		sender, err := q.GetUser(ctx, lockedDoc.SenderID)
		if err != nil {
			return fmt.Errorf("load decline notification sender: %w", err)
		}
		notificationMessages, err = e.prepareNotificationTx(ctx, q, dispatch.KindDeclined, sender.Email, dispatch.TemplateContext{
			DocumentName:  lockedDoc.Name,
			SenderName:    sender.Name,
			SenderEmail:   sender.Email,
			RecipientName: freshRec.Name,
			OrgName:       e.OrgName,
			DeclineReason: reason,
		})
		if err != nil {
			return fmt.Errorf("prepare decline notification: %w", err)
		}
	}
	declinedPayload, err := responseAuditPayload(map[string]any{"reason": reason}, evidence.Notice)
	if err != nil {
		return fmt.Errorf("bind decline notice evidence: %w", err)
	}
	declinedEvent := audit.Entry{
		OrgID: doc.OrgID, DocumentID: &rec.DocumentID, RecipientID: &rec.ID,
		Kind:      audit.KindDocumentDeclined,
		IP:        evidence.IP,
		UserAgent: evidence.UserAgent,
		Payload:   declinedPayload,
	}
	pendingAudit, err := e.Audit.LogTx(ctx, tx, declinedEvent)
	if err != nil {
		return fmt.Errorf("audit decline: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit decline: %w", err)
	}
	e.Audit.Publish(pendingAudit)
	e.deliverPostCommitEmails(notificationMessages)
	return nil
}

// RequestChanges pauses an active document for negotiation: instead of signing,
// the recipient asks for changes. The document moves to changes_requested (which
// gates all signing until the sender revises and re-sends), the request is
// recorded, and the sender is notified. Unlike Decline this is reversible: the
// sender revises the document and re-sends the new draft.
// ChangeRequestInput is one inline change request: a comment, optionally
// anchored to a marked span of text in a specific block, optionally carrying a
// proposed replacement.
type ChangeRequestInput struct {
	Message   string
	BlockID   string
	Quote     string
	Context   string
	Proposed  string
	IP        string
	UserAgent string
	Notice    Article13NoticeEvidence
}

func (e *Engine) RequestChanges(ctx context.Context, rc *RecipientContext, in ChangeRequestInput) error {
	if err := validateNoticeEvidence(rc, in.Notice); err != nil {
		return err
	}
	rec := rc.Recipient
	doc := rc.Document
	if strings.TrimSpace(in.Message) == "" && strings.TrimSpace(in.Proposed) == "" {
		return errors.New("describe the change you need")
	}

	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)

	lockedDoc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return fmt.Errorf("lock document: %w", err)
	}
	if err := ValidateLockedNoticeEvidence(rc, lockedDoc, in.Notice); err != nil {
		return err
	}
	// Allow marking several spans during the same pause.
	if lockedDoc.Status != "sent" && lockedDoc.Status != "in_progress" && lockedDoc.Status != "changes_requested" {
		return ErrDocumentNotSignable
	}
	if err := rejectUnsupportedEnvelopeTransition(lockedDoc, "request changes"); err != nil {
		return err
	}
	freshRec, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: rec.ID, OrgID: doc.OrgID})
	if err != nil {
		return err
	}
	if freshRec.DocumentID != doc.ID || !recipientCanRequestChanges(freshRec.Role, freshRec.Status) {
		return ErrRecipientNotEligibleForChanges
	}
	// Negotiation reopens editable content. Once any party has signed,
	// accepted, or filled a field, pausing this in-place ceremony would either
	// brick it (Revise must refuse) or let auto-apply mutate already-consented
	// content. A superseding-document model is required for that workflow.
	captured, err := documentHasCapturedEvidence(ctx, q, doc.ID)
	if err != nil {
		return fmt.Errorf("inspect change-request evidence: %w", err)
	}
	if captured {
		return ErrRevisionWouldDestroyEvidence
	}
	cr, err := q.CreateChangeRequest(ctx, generated.CreateChangeRequestParams{
		DocumentID:  doc.ID,
		RecipientID: pgtype.UUID{Bytes: rec.ID, Valid: true},
		Message:     in.Message,
		BlockID:     in.BlockID,
		Quote:       in.Quote,
		Context:     in.Context,
		Proposed:    in.Proposed,
	})
	if err != nil {
		return fmt.Errorf("record change request: %w", err)
	}
	if _, err := q.RequestChangesOnDocument(ctx, generated.RequestChangesOnDocumentParams{ID: doc.ID, OrgID: doc.OrgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDocumentNotSignable
		}
		return err
	}
	var notificationMessages []dispatch.Message
	if e.Mailer != nil {
		sender, err := q.GetUser(ctx, lockedDoc.SenderID)
		if err != nil {
			return fmt.Errorf("load change-request notification sender: %w", err)
		}
		approveURL, denyURL := "", ""
		if e.ActionSecret != "" {
			base := actiontoken.Claims{Kind: "cr", OrgID: lockedDoc.OrgID.String(), DocID: lockedDoc.ID.String(), TargetID: cr.ID.String()}
			approve := base
			approve.Action = "approve"
			deny := base
			deny.Action = "deny"
			approveURL = strings.TrimRight(e.BaseURL, "/") + "/a/cr?t=" + actiontoken.Mint(e.ActionSecret, approve, e.now(), 14*24*time.Hour)
			denyURL = strings.TrimRight(e.BaseURL, "/") + "/a/cr?t=" + actiontoken.Mint(e.ActionSecret, deny, e.now(), 14*24*time.Hour)
		}
		notificationMessages, err = e.prepareNotificationTx(ctx, q, dispatch.KindChangesRequested, sender.Email, dispatch.TemplateContext{
			DocumentName:   lockedDoc.Name,
			SenderName:     sender.Name,
			SenderEmail:    sender.Email,
			RecipientName:  freshRec.Name,
			OrgName:        e.OrgName,
			DeclineReason:  in.Message,
			ChangeQuote:    in.Quote,
			ChangeContext:  in.Context,
			ChangeProposed: in.Proposed,
			OpenURL:        strings.TrimRight(e.BaseURL, "/") + "/documents/" + lockedDoc.ID.String(),
			ApproveURL:     approveURL,
			DenyURL:        denyURL,
		})
		if err != nil {
			return fmt.Errorf("prepare change-request notification: %w", err)
		}
	}
	changePayload, err := responseAuditPayload(map[string]any{
		"message": in.Message, "block_id": in.BlockID, "quote": in.Quote,
	}, in.Notice)
	if err != nil {
		return fmt.Errorf("bind change-request notice evidence: %w", err)
	}
	changeEvent := audit.Entry{
		OrgID: doc.OrgID, DocumentID: &rec.DocumentID, RecipientID: &rec.ID,
		Kind:      audit.KindChangesRequested,
		IP:        in.IP,
		UserAgent: in.UserAgent,
		Payload:   changePayload,
	}
	pendingAudit, err := e.Audit.LogTx(ctx, tx, changeEvent)
	if err != nil {
		return fmt.Errorf("audit change request: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit change request: %w", err)
	}
	e.Audit.Publish(pendingAudit)
	e.deliverPostCommitEmails(notificationMessages)
	return nil
}

func recipientCanRequestChanges(role, status string) bool {
	if !recipients.CanRespond(role) {
		return false
	}
	switch status {
	case "pending", "sent", "viewed":
		return true
	default:
		return false
	}
}

func rejectUnsupportedEnvelopeTransition(doc *generated.Document, transition string) error {
	if doc != nil && doc.IsEnvelope {
		return fmt.Errorf("%w: %s", ErrEnvelopeTransitionUnsupported, transition)
	}
	return nil
}

// ResolveChange approves or denies one inline change request. On approve, if the
// org's change_approval_mode is auto_apply and the request carries a marked span
// plus a proposed replacement, the marked text is swapped in the block in place;
// otherwise approval is recorded for the sender to apply during Revise.
func (e *Engine) ResolveChange(ctx context.Context, orgID, docID, crID uuid.UUID, approve bool) (*generated.ChangeRequest, error) {
	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)

	// Lock parent first, matching Revise's UPDATE documents -> UPDATE
	// change_requests ordering. This serializes revise versus resolve without a
	// lock-order inversion.
	doc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: docID, OrgID: orgID})
	if err != nil {
		return nil, err
	}
	if doc.Status != "changes_requested" {
		return nil, ErrNotRevisable
	}
	cr, err := q.GetChangeRequestForUpdate(ctx, generated.GetChangeRequestForUpdateParams{ID: crID, OrgID: orgID})
	if err != nil {
		return nil, err
	}
	if cr.DocumentID != docID {
		return nil, errors.New("change request does not belong to this document")
	}
	if !changeRequestCanResolve(cr.Status) {
		return nil, ErrChangeAlreadyResolved
	}
	resolution := "denied"
	if approve {
		resolution = "approved"
		org, err := q.GetOrg(ctx, orgID)
		if err != nil {
			return nil, fmt.Errorf("load change approval mode: %w", err)
		}
		if org.ChangeApprovalMode == "auto_apply" {
			captured, err := documentHasCapturedEvidence(ctx, q, docID)
			if err != nil {
				return nil, fmt.Errorf("inspect auto-apply evidence: %w", err)
			}
			if captured {
				return nil, ErrRevisionWouldDestroyEvidence
			}
			if err := applyChangeToLockedDocument(ctx, q, doc, cr); err != nil {
				return nil, err
			}
		}
	}
	resolved, err := q.ResolveChangeRequest(ctx, generated.ResolveChangeRequestParams{
		ID: crID, DocumentID: docID, Resolution: pgtype.Text{String: resolution, Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrChangeAlreadyResolved
		}
		return nil, err
	}
	resolutionEvent := audit.Entry{
		OrgID: orgID, DocumentID: &docID,
		Kind:    audit.KindChangesRequested,
		Payload: map[string]any{"change_request": crID.String(), "resolution": resolution},
	}
	pendingAudit, err := e.Audit.LogTx(ctx, tx, resolutionEvent)
	if err != nil {
		return nil, fmt.Errorf("audit change resolution: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit change resolution: %w", err)
	}
	e.Audit.Publish(pendingAudit)
	return resolved, nil
}

func changeRequestCanResolve(status string) bool { return status == "open" }

// applyChangeToLockedDocument swaps the first quoted occurrence in the already
// row-locked document. Its write shares ResolveChange's transaction, so an
// apply error rolls back both the block mutation and the request resolution.
func applyChangeToLockedDocument(ctx context.Context, q *generated.Queries, doc *generated.Document, cr *generated.ChangeRequest) error {
	if cr.BlockID == "" || cr.Quote == "" || cr.Proposed == "" {
		return nil
	}
	raw, changed, err := replaceBlockQuote(doc.BlocksJson, cr.BlockID, cr.Quote, cr.Proposed)
	if err != nil {
		return fmt.Errorf("parse blocks for change: %w", err)
	}
	if !changed {
		return nil
	}
	if _, err := q.ApplyBlocksForChange(ctx, generated.ApplyBlocksForChangeParams{
		ID: doc.ID, OrgID: doc.OrgID, BlocksJson: raw,
	}); err != nil {
		return fmt.Errorf("apply approved change: %w", err)
	}
	return nil
}

func replaceBlockQuote(raw json.RawMessage, blockID, quote, proposed string) (json.RawMessage, bool, error) {
	tree, err := blocks.ParseCanonicalTree(raw)
	if err != nil {
		return nil, false, err
	}
	changed := false
	var visit func(bs []blocks.Block)
	visit = func(bs []blocks.Block) {
		for i := range bs {
			if !changed && bs[i].ID == blockID && strings.Contains(bs[i].Text, quote) {
				bs[i].Text = strings.Replace(bs[i].Text, quote, proposed, 1)
				changed = true
			}
			if len(bs[i].Content) > 0 {
				visit(bs[i].Content)
			}
		}
	}
	visit(tree.Blocks)
	if !changed {
		return raw, false, nil
	}
	updated, err := json.Marshal(tree)
	if err != nil {
		return nil, false, err
	}
	return updated, true, nil
}

// SignerComment posts a comment from a recipient on the shared document thread
// and emails the sender.
func (e *Engine) SignerComment(ctx context.Context, rc *RecipientContext, body string, evidence ParticipantResponseEvidence) (*generated.DocumentComment, error) {
	if err := validateNoticeEvidence(rc, evidence.Notice); err != nil {
		return nil, err
	}
	if err := validateCommentBody(body); err != nil {
		return nil, err
	}
	rec := rc.Recipient
	doc := rc.Document
	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)

	lockedDoc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, fmt.Errorf("lock document for signer comment: %w", err)
	}
	if err := ValidateLockedNoticeEvidence(rc, lockedDoc, evidence.Notice); err != nil {
		return nil, err
	}
	if err := checkDocumentCommentable(lockedDoc); err != nil {
		return nil, err
	}
	freshRec, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: rec.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, err
	}
	if freshRec.DocumentID != lockedDoc.ID {
		return nil, ErrDocumentNotCommentable
	}
	c, err := q.CreateComment(ctx, generated.CreateCommentParams{
		DocumentID:  doc.ID,
		RecipientID: pgtype.UUID{Bytes: rec.ID, Valid: true},
		AuthorName:  rec.Name,
		AuthorSide:  "signer",
		Body:        body,
	})
	if err != nil {
		return nil, err
	}
	var notificationMessages []dispatch.Message
	if e.Mailer != nil {
		sender, err := q.GetUser(ctx, lockedDoc.SenderID)
		if err != nil {
			return nil, fmt.Errorf("load signer-comment notification sender: %w", err)
		}
		notificationMessages, err = e.prepareNotificationTx(ctx, q, dispatch.KindNewComment, sender.Email, dispatch.TemplateContext{
			DocumentName:  lockedDoc.Name,
			SenderName:    sender.Name,
			SenderEmail:   sender.Email,
			RecipientName: rec.Name,
			OrgName:       e.OrgName,
			DeclineReason: body,
			OpenURL:       strings.TrimRight(e.BaseURL, "/") + "/documents/" + doc.ID.String(),
		})
		if err != nil {
			return nil, fmt.Errorf("prepare signer-comment notification: %w", err)
		}
	}
	commentPayload, err := responseAuditPayload(map[string]any{"side": "signer"}, evidence.Notice)
	if err != nil {
		return nil, fmt.Errorf("bind signer-comment notice evidence: %w", err)
	}
	pendingAudit, err := e.Audit.LogTx(ctx, tx, audit.Entry{
		OrgID: doc.OrgID, DocumentID: &doc.ID, RecipientID: &rec.ID,
		Kind:      audit.KindCommentPosted,
		IP:        evidence.IP,
		UserAgent: evidence.UserAgent,
		Payload:   commentPayload,
	})
	if err != nil {
		return nil, fmt.Errorf("audit signer comment: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit signer comment: %w", err)
	}
	e.Audit.Publish(pendingAudit)
	e.deliverPostCommitEmails(notificationMessages)
	return c, nil
}

// SenderComment posts a comment from the sending org on the shared thread and
// emails each signer recipient.
func (e *Engine) SenderComment(ctx context.Context, orgID, docID, userID uuid.UUID, authorName, body string) (*generated.DocumentComment, error) {
	if err := validateCommentBody(body); err != nil {
		return nil, err
	}
	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)
	doc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: docID, OrgID: orgID})
	if err != nil {
		return nil, fmt.Errorf("lock document for sender comment: %w", err)
	}
	if err := checkDocumentCommentable(doc); err != nil {
		return nil, err
	}
	c, err := q.CreateComment(ctx, generated.CreateCommentParams{
		DocumentID: docID,
		UserID:     pgtype.UUID{Bytes: userID, Valid: true},
		AuthorName: authorName,
		AuthorSide: "sender",
		Body:       body,
	})
	if err != nil {
		return nil, err
	}
	var notificationMessages []dispatch.Message
	if e.Mailer != nil {
		recs, err := q.ListRecipientsByDocument(ctx, docID)
		if err != nil {
			return nil, fmt.Errorf("list sender-comment notification recipients: %w", err)
		}
		for _, r := range recs {
			if !recipientReceivesSenderComment(r) {
				continue
			}
			messages, err := e.prepareNotificationTx(ctx, q, dispatch.KindNewComment, r.Email, dispatch.TemplateContext{
				DocumentName:  doc.Name,
				OrgName:       e.OrgName,
				RecipientName: authorName,
				DeclineReason: body,
			})
			if err != nil {
				return nil, fmt.Errorf("prepare sender-comment notification: %w", err)
			}
			notificationMessages = append(notificationMessages, messages...)
		}
	}
	pendingAudit, err := e.Audit.LogTx(ctx, tx, audit.Entry{
		OrgID: orgID, DocumentID: &docID,
		Kind: audit.KindCommentPosted, Payload: map[string]any{"side": "sender"},
	})
	if err != nil {
		return nil, fmt.Errorf("audit sender comment: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit sender comment: %w", err)
	}
	e.Audit.Publish(pendingAudit)
	e.deliverPostCommitEmails(notificationMessages)
	return c, nil
}

const (
	maxCommentBodyRunes = 10_000
	maxCommentBodyBytes = 40 * 1024
)

// validateCommentBody bounds the value copied into the comment row, audit
// context, and notification outbox. The rune ceiling is user-facing; the byte
// ceiling independently bounds storage for multi-byte Unicode input.
func validateCommentBody(body string) error {
	if !utf8.ValidString(body) {
		return errors.New("comment must be valid UTF-8")
	}
	if strings.TrimSpace(body) == "" {
		return errors.New("comment is empty")
	}
	if len(body) > maxCommentBodyBytes {
		return fmt.Errorf("comment must be at most %d bytes", maxCommentBodyBytes)
	}
	if utf8.RuneCountInString(body) > maxCommentBodyRunes {
		return fmt.Errorf("comment must be at most %d characters", maxCommentBodyRunes)
	}
	return nil
}

// checkDocumentCommentable is deliberately narrower than a stale-token read:
// all comment mutations take the document row lock and call this helper before
// inserting both the comment and its audit event. In particular, finalizing is
// non-interactive, so the certificate's captured chain head/event set cannot be
// extended by a racing sender or email-reply comment.
func checkDocumentCommentable(doc *generated.Document) error {
	if doc == nil {
		return ErrDocumentNotCommentable
	}
	switch doc.Status {
	case "sent", "in_progress", "changes_requested":
		return nil
	default:
		return ErrDocumentNotCommentable
	}
}

// Revise reopens a changes_requested document to draft only when no legal
// response has yet been captured. The current schema has no superseding
// ceremony/version relation for signatures and acceptances; mutating those
// rows in place would destroy evidence, so such revisions fail closed.
func (e *Engine) Revise(ctx context.Context, orgID, docID uuid.UUID) (*generated.Document, error) {
	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)

	locked, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: docID, OrgID: orgID})
	if err != nil {
		return nil, err
	}
	if locked.Status != "changes_requested" {
		return nil, ErrNotRevisable
	}
	if err := rejectUnsupportedEnvelopeTransition(locked, "revise"); err != nil {
		return nil, err
	}
	captured, err := documentHasCapturedEvidence(ctx, q, docID)
	if err != nil {
		return nil, fmt.Errorf("inspect revision evidence: %w", err)
	}
	if captured {
		return nil, ErrRevisionWouldDestroyEvidence
	}

	doc, err := q.ReopenDocumentToDraft(ctx, generated.ReopenDocumentToDraftParams{ID: docID, OrgID: orgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotRevisable
		}
		return nil, err
	}
	if err := q.ResolveChangeRequests(ctx, docID); err != nil {
		return nil, err
	}
	if err := q.ResetRecipientsForRevision(ctx, docID); err != nil {
		return nil, err
	}
	// The paused ceremony credential must not survive into an editable draft.
	// Send will mint a fresh token/hash/expiry for the superseding ceremony.
	if err := q.InvalidateRecipientTokens(ctx, docID); err != nil {
		return nil, fmt.Errorf("invalidate revised ceremony tokens: %w", err)
	}
	revisedEvent := audit.Entry{
		OrgID: orgID, DocumentID: &docID,
		Kind: audit.KindDocumentRevised,
	}
	pendingAudit, err := e.Audit.LogTx(ctx, tx, revisedEvent)
	if err != nil {
		return nil, fmt.Errorf("audit revision: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit revise: %w", err)
	}
	e.Audit.Publish(pendingAudit)
	return doc, nil
}

func revisionHasCapturedEvidence(recipients []*generated.Recipient, signatures []*generated.Signature, fields []*generated.DocumentField) bool {
	if len(signatures) != 0 {
		return true
	}
	for _, recipient := range recipients {
		if recipient == nil {
			continue
		}
		if recipient.Status == "signed" || recipient.Status == "accepted" || recipient.SignedAt.Valid {
			return true
		}
	}
	for _, field := range fields {
		if field != nil && (field.Value.Valid || field.CompletedAt.Valid) {
			return true
		}
	}
	return false
}

func documentHasCapturedEvidence(ctx context.Context, q *generated.Queries, docID uuid.UUID) (bool, error) {
	recipients, err := q.ListRecipientsByDocument(ctx, docID)
	if err != nil {
		return false, err
	}
	signatures, err := q.ListSignaturesByDocument(ctx, docID)
	if err != nil {
		return false, err
	}
	fields, err := q.ListFieldsByDocument(ctx, docID)
	if err != nil {
		return false, err
	}
	return revisionHasCapturedEvidence(recipients, signatures, fields), nil
}

// RenderForSigner returns the HTML body of the document with variables
// applied and signed signatures (if any) inlined. Pre-send and during-sign
// it shows "Signature pending" placeholders for unsigned slots so the
// signer sees the layout they're filling in.
//
// Phase 8.6.1: when the document is an envelope, we concatenate every
// child's rendered body (page-break separated, with a heading naming
// the child) so the signer reads the whole bundle in one scroll. The
// envelope's own block tree is empty by construction; we render only
// the children + a banner at the top noting the envelope title.
func (e *Engine) RenderForSigner(ctx context.Context, rc *RecipientContext) (string, error) {
	brandCSS := ""
	if e.BrandingCSS != nil {
		brandCSS = e.BrandingCSS(ctx, rc.Document)
	}

	if rc.Document.IsEnvelope {
		if e.EnvelopeChildren == nil {
			return "", errors.New("render signer document: envelope children unavailable")
		}
		body, err := e.renderEnvelopeBody(ctx, rc.Document, rc.Recipient.Locale)
		if err != nil {
			return "", err
		}
		return buildHTMLDocument(brandCSS, body, ""), nil
	}

	tree, vars, err := frozenBlockDocument(rc.Document)
	if err != nil {
		return "", fmt.Errorf("render signer document: %w", err)
	}
	body, err := e.renderSignedHTML(ctx, tree, rc.Document.ID, vars, rc.Recipient.Locale)
	if err != nil {
		return "", err
	}
	return buildHTMLDocument(brandCSS, body, ""), nil
}

// renderEnvelopeBody concatenates every child's HTML render with a
// heading + page break between them. The signer reads the whole bundle
// in one scroll; the recipient's signatures stamp onto the appropriate
// children at sign time based on each signature_field's
// target_document_id attribute (defaults to the envelope id, meaning
// the field belongs to the envelope wrapper).
func (e *Engine) renderEnvelopeBody(ctx context.Context, envelope *generated.Document, locale string) (string, error) {
	if envelope == nil || !envelope.IsEnvelope {
		return "", errors.New("render envelope body: invalid envelope")
	}
	if e.EnvelopeChildren == nil {
		return "", errors.New("render envelope body: envelope children unavailable")
	}
	children, err := e.EnvelopeChildren(ctx, envelope)
	if err != nil {
		return "", fmt.Errorf("render envelope body: list children: %w", err)
	}
	return e.renderEnvelopeChildrenBody(ctx, envelope, children, locale)
}

// renderEnvelopeChildrenBody renders an already-loaded snapshot. Finalization
// uses the same child slice for both this body and its signed manifest, so the
// certificate cannot accidentally commit one DB read while the PDF renders a
// later one.
func (e *Engine) renderEnvelopeChildrenBody(ctx context.Context, envelope *generated.Document, children []*generated.Document, locale string) (string, error) {
	if envelope == nil || !envelope.IsEnvelope {
		return "", errors.New("render envelope body: invalid envelope")
	}
	if len(children) == 0 {
		return "", errors.New("render envelope body: envelope has no children")
	}
	var sb strings.Builder
	fmt.Fprintf(&sb,
		`<section class="hash-envelope-banner"><h1>%s</h1><p class="hash-envelope-note">This envelope bundles %d documents that are signed together as a single legal instrument.</p></section>`,
		htmlEscape(envelope.Name), len(children))

	for i, child := range children {
		if child == nil {
			return "", fmt.Errorf("render envelope body: child %d is nil", i+1)
		}
		if !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != envelope.ID {
			return "", fmt.Errorf("render envelope body: child %s is not attached", child.ID)
		}
		if child.IsEnvelope {
			return "", fmt.Errorf("render envelope body: child %s is itself an envelope", child.ID)
		}
		if !envelopeChildStatusMatchesParent(envelope.Status, child.Status) {
			return "", fmt.Errorf("render envelope body: child %s status %s does not match envelope status %s", child.ID, child.Status, envelope.Status)
		}
		if child.SourceKind != "blocks" {
			return "", fmt.Errorf("render envelope body: child %s is not a blocks document", child.ID)
		}
		tree, vars, err := frozenBlockDocument(child)
		if err != nil {
			return "", fmt.Errorf("render envelope body: child %s: %w", child.ID, err)
		}
		// Recipients and signature rows belong to the envelope ceremony, not
		// to each child row. Render every child field against the envelope ID
		// so signer/approver spans appear in the final combined body.
		childBody, err := e.renderSignedHTML(ctx, tree, envelope.ID, vars, locale)
		if err != nil {
			return "", fmt.Errorf("render envelope body: render child %s: %w", child.ID, err)
		}
		if i > 0 {
			sb.WriteString(`<div class="hash-envelope-pagebreak" style="page-break-before:always;"></div>`)
		}
		fmt.Fprintf(&sb,
			`<section class="hash-envelope-child" data-child-id="%s"><h2>%d. %s</h2>`,
			child.ID, i+1, htmlEscape(child.Name))
		sb.WriteString(childBody)
		sb.WriteString(`</section>`)
	}
	return sb.String(), nil
}

// MarkViewed flips status pending→viewed (idempotent for already-viewed)
// and emits an audit event the first time it happens.
func (e *Engine) MarkViewed(ctx context.Context, rc *RecipientContext, evidence ParticipantResponseEvidence) error {
	if err := validateNoticeEvidence(rc, evidence.Notice); err != nil {
		return err
	}
	rec := rc.Recipient
	doc := rc.Document
	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)

	lockedDoc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return fmt.Errorf("lock document for viewed event: %w", err)
	}
	if err := ValidateLockedNoticeEvidence(rc, lockedDoc, evidence.Notice); err != nil {
		return err
	}
	if err := checkActiveCeremonyAccess(lockedDoc); err != nil {
		return err
	}
	freshRec, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: rec.ID, OrgID: doc.OrgID})
	if err != nil {
		return err
	}
	if freshRec.DocumentID != lockedDoc.ID {
		return ErrDocumentNotSignable
	}
	if freshRec.Status != "pending" && freshRec.Status != "sent" {
		return nil
	}
	if err := q.SetRecipientStatus(ctx, generated.SetRecipientStatusParams{
		ID: rec.ID, DocumentID: rec.DocumentID,
		Status:         "viewed",
		DeclinedReason: pgtype.Text{},
	}); err != nil {
		return err
	}
	viewPayload, err := responseAuditPayload(nil, evidence.Notice)
	if err != nil {
		return fmt.Errorf("bind view notice evidence: %w", err)
	}
	pendingAudit, err := e.Audit.LogTx(ctx, tx, audit.Entry{
		OrgID: lockedDoc.OrgID, DocumentID: &rec.DocumentID, RecipientID: &rec.ID,
		Kind:      audit.KindDocumentViewed,
		IP:        evidence.IP,
		UserAgent: evidence.UserAgent,
		Payload:   viewPayload,
	})
	if err != nil {
		return fmt.Errorf("audit document view: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit document view: %w", err)
	}
	e.Audit.Publish(pendingAudit)
	return nil
}

// preparedSignature holds a rendered span. Immutable storage happens only
// after the authoritative transaction checks pass.
type preparedSignature struct {
	fieldBlockID string
	imgKey       string
	imgVersionID string
	span         []byte
	sum          [32]byte
}

// prepareSignature renders the signature span and resolves the recipient's
// signature field. It deliberately performs zero storage writes.
func (e *Engine) prepareSignature(ctx context.Context, doc *generated.Document, rec *generated.GetRecipientByTokenHashRow, in SignInput) (*preparedSignature, error) {
	if err := render.ValidateSignatureName(in.TypedName); err != nil {
		return nil, fmt.Errorf("prepare signature: %w", err)
	}
	// PDF-source documents have no block tree: the signature stamps onto the
	// uploaded PDF at the recipient's signature field coordinates during
	// finalize. We still render the span so the audit cert and the
	// signature row's ImageSha256 are populated identically to the blocks path.
	if doc.SourceKind != "blocks" {
		span, err := render.RenderSignatureSpan(in.TypedName, in.Font)
		if err != nil {
			return nil, fmt.Errorf("prepare signature: %w", err)
		}
		sum := sha256.Sum256([]byte(span))
		return &preparedSignature{fieldBlockID: "", span: []byte(span), sum: sum}, nil
	}

	fieldBlockID, err := e.signatureFieldBlockID(ctx, doc, rec.Role)
	if err != nil {
		return nil, err
	}
	span, err := render.RenderSignatureSpan(in.TypedName, in.Font)
	if err != nil {
		return nil, fmt.Errorf("prepare signature: %w", err)
	}
	sum := sha256.Sum256([]byte(span))
	return &preparedSignature{fieldBlockID: fieldBlockID, span: []byte(span), sum: sum}, nil
}

// storePreparedSignature uses a deterministic content-addressed key. Replays
// cannot create unbounded WORM objects, and a failed later DB insert can only
// orphan the same idempotent key.
func (e *Engine) storePreparedSignature(ctx context.Context, doc *generated.Document, recID uuid.UUID, prep *preparedSignature) error {
	if e.Storage == nil || doc == nil || prep == nil || len(prep.span) == 0 {
		return errors.New("store signature span: evidence storage or rendered span unavailable")
	}
	prep.imgKey = path.Join(
		"org", doc.OrgID.String(), "documents", doc.ID.String(), "signatures",
		recID.String()+"-"+hex.EncodeToString(prep.sum[:])+".html",
	)
	if !doc.SentAt.Valid || doc.SentAt.Time.IsZero() {
		return errors.New("store signature span: authoritative sent timestamp is unavailable")
	}
	retainUntil := storage.EvidenceRetentionDeadline(doc.SentAt.Time, article13.RetentionYearsV1)
	stored, err := e.Storage.PutEvidenceVersioned(ctx, prep.imgKey, "text/html", prep.span, retainUntil)
	if err != nil {
		return fmt.Errorf("store signature span: %w", err)
	}
	if stored.SHA256 != prep.sum || strings.TrimSpace(stored.VersionID) == "" {
		return errors.New("store signature span: storage digest mismatch")
	}
	prep.imgVersionID = stored.VersionID
	return nil
}

// signatureFieldBlockID finds the field assigned to a signing role. Envelope
// fields live in child trees while their ceremony/signature rows live on the
// envelope, so the stored identifier includes the child ID to stay unambiguous
// even when two imported child documents reused the same block ID.
func (e *Engine) signatureFieldBlockID(ctx context.Context, doc *generated.Document, role string) (string, error) {
	if doc == nil {
		return "", errors.New("find signature field: nil document")
	}
	if !doc.IsEnvelope {
		tree, vars, err := frozenBlockDocument(doc)
		if err != nil {
			return "", fmt.Errorf("find signature field: %w", err)
		}
		field, err := findActiveSignatureFieldFor(tree, role, vars)
		if err != nil {
			return "", fmt.Errorf("find signature field: %w", err)
		}
		if field == nil {
			return "", fmt.Errorf("no signature field assigned to role %q", role)
		}
		return field.ID, nil
	}
	if e.EnvelopeChildren == nil {
		return "", errors.New("find signature field: envelope children unavailable")
	}
	children, err := e.EnvelopeChildren(ctx, doc)
	if err != nil {
		return "", fmt.Errorf("find signature field: list envelope children: %w", err)
	}
	if len(children) == 0 {
		return "", errors.New("find signature field: envelope has no children")
	}
	for i, child := range children {
		if child == nil {
			return "", fmt.Errorf("find signature field: child %d is nil", i+1)
		}
		if child.SourceKind != "blocks" {
			return "", fmt.Errorf("find signature field: child %s is not a blocks document", child.ID)
		}
		tree, vars, err := frozenBlockDocument(child)
		if err != nil {
			return "", fmt.Errorf("find signature field: child %s: %w", child.ID, err)
		}
		field, err := findActiveSignatureFieldFor(tree, role, vars)
		if err != nil {
			return "", fmt.Errorf("find signature field: child %s: %w", child.ID, err)
		}
		if field != nil {
			return child.ID.String() + ":" + field.ID, nil
		}
	}
	return "", fmt.Errorf("no envelope signature field assigned to role %q", role)
}

// insertSignatureRow writes the signature + its field row through the supplied
// tx-scoped queries. A unique-index conflict (concurrent double-POST) returns
// ErrAlreadySigned rather than inserting a duplicate.
func (e *Engine) insertSignatureRow(ctx context.Context, q *generated.Queries, doc *generated.Document, recID uuid.UUID, fieldRow *generated.DocumentField, prep *preparedSignature, in SignInput) (*generated.Signature, error) {
	if fieldRow == nil || prep == nil || prep.imgKey == "" || strings.TrimSpace(prep.imgVersionID) == "" {
		return nil, errors.New("insert signature: prepared field and evidence are required")
	}
	if err := render.ValidateSignatureName(in.TypedName); err != nil {
		return nil, fmt.Errorf("insert signature: %w", err)
	}
	var ipPtr *netip.Addr
	if in.IP != "" {
		if a, perr := netip.ParseAddr(in.IP); perr == nil {
			ipPtr = &a
		}
	}
	sig, err := q.InsertSignature(ctx, generated.InsertSignatureParams{
		DocumentID:      doc.ID,
		RecipientID:     recID,
		FieldID:         fieldRow.ID,
		Font:            in.Font,
		TypedName:       in.TypedName,
		ImageStorageKey: prep.imgKey,
		ImageSha256:     prep.sum[:],
		ImageVersionID:  pgtype.Text{String: prep.imgVersionID, Valid: true},
		SignerIp:        ipPtr,
		SignerUa:        textOrNull(in.UserAgent),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// ON CONFLICT (document_id, recipient_id) DO NOTHING returned no row:
		// this recipient already has a signature (concurrent double-POST).
		return nil, ErrAlreadySigned
	}
	if err != nil {
		return nil, fmt.Errorf("insert signature row: %w", err)
	}
	return sig, nil
}

// finalize renders the final PDF + audit cert via Gotenberg and persists the
// terminal state. It is serialized per-document by a Postgres advisory lock so
// the inline last-signer path and the finalize-retry worker never double-
// render against the same storage keys, and it is idempotent: a document that
// already has its final PDF + cert short-circuits.
//
// Returns didFinalize=false (with the existing keys) when the document was
// already finalized, so callers don't re-emit completion events/emails.
func (e *Engine) finalize(ctx context.Context, orgID, docID uuid.UUID, capture *completionCredentialCapture) (finalKey, certKey string, didFinalize bool, err error) {
	// Per-document finalize mutex. pg_try_advisory_lock returns immediately;
	// if another finalize holds it, bail with ErrFinalizeInProgress and let
	// that one (or the retry worker) complete.
	conn, err := e.Pool.Acquire(ctx)
	if err != nil {
		return "", "", false, err
	}
	defer conn.Release()
	lockKey := advisoryLockKey(docID)
	var got bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lockKey).Scan(&got); err != nil { //nolint:rawsql
		return "", "", false, err
	}
	if !got {
		return "", "", false, ErrFinalizeInProgress
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", lockKey) }() //nolint:rawsql

	doc, err := e.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: docID, OrgID: orgID})
	if err != nil {
		return "", "", false, err
	}
	// Idempotency: already finalized.
	if doc.FinalPdfKey.Valid && doc.AuditCertKey.Valid {
		return doc.FinalPdfKey.String, doc.AuditCertKey.String, false, nil
	}
	if !doc.RequiresSignature {
		return "", "", false, ErrNotAcknowledgement
	}
	if doc.Status == "finalizing" {
		if _, ierr := e.Queries.GetDocumentFinalizationIntent(ctx, generated.GetDocumentFinalizationIntentParams{
			DocumentID: doc.ID, OrgID: doc.OrgID,
		}); ierr == nil {
			completed, did, rerr := e.resumeDocumentFinalization(ctx, conn, doc, capture)
			if rerr != nil || completed == nil {
				return "", "", false, rerr
			}
			return completed.FinalPdfKey.String, completed.AuditCertKey.String, did, nil
		} else if !errors.Is(ierr, pgx.ErrNoRows) {
			return "", "", false, fmt.Errorf("load signature finalization intent: %w", ierr)
		}
		// The process may have exited after claiming finalizing but before it
		// could persist the staged-object intent. Re-render below from the now
		// frozen ceremony state.
	} else if doc.Status == "in_progress" {
		doc, err = e.claimDocumentFinalizing(ctx, conn, doc.OrgID, doc.ID, "signature")
		if err != nil {
			return "", "", false, err
		}
	} else {
		return "", "", false, ErrDocumentRevisedDuringFinalize
	}
	doc, err = e.ensureDocumentSourceVersions(ctx, doc)
	if err != nil {
		return "", "", false, err
	}
	if err := e.ensureSignatureVersions(ctx, doc.ID); err != nil {
		return "", "", false, err
	}
	retainUntil, err := finalizationRetentionDeadline(doc)
	if err != nil {
		return "", "", false, fmt.Errorf("finalize document: %w", err)
	}

	// From this point onward the durable finalizing state closes every
	// interactive/audit-event path for this document. Capture the chain head and
	// document-event set only after that boundary, never while the ceremony is
	// still able to accept a decline, change request, view, reminder, or field.

	// Load one immutable child snapshot for both the body render and the signed
	// terminal manifest. Envelope send freezes content and draft-only topology
	// guards prevent either set from changing after the ceremony starts.
	var envelopeChildren []*generated.Document
	var manifestHTML *string
	if doc.IsEnvelope {
		envelopeChildren, err = e.ensureEnvelopeChildrenEvidenceVersions(ctx, doc)
		if err != nil {
			return "", "", false, err
		}
		manifest, merr := envelopes.BuildTerminalManifest(doc, envelopeChildren)
		if merr != nil {
			return "", "", false, fmt.Errorf("finalize envelope: build terminal manifest: %w", merr)
		}
		section := manifest.HTMLSection()
		if section == "" {
			return "", "", false, errors.New("finalize envelope: terminal manifest is empty")
		}
		manifestHTML = &section
	}
	brandCSS := ""
	if e.BrandingCSS != nil {
		brandCSS = e.BrandingCSS(ctx, doc)
	}

	// Render the exact contract body first. The audit certificate is a separate
	// artifact and signs this body's SHA-256. Keeping it separate avoids the
	// impossible self-hash cycle that occurs when a certificate claims the hash
	// of a PDF that contains the certificate itself.
	var pdfBytes []byte
	if doc.SourceKind == "blocks" {
		var signedHTML string
		var rerr error
		if doc.IsEnvelope {
			signedHTML, rerr = e.renderEnvelopeChildrenBody(ctx, doc, envelopeChildren, "en")
		} else {
			signedHTML, rerr = e.renderFinalBlocksBody(ctx, doc, "en")
		}
		if rerr != nil {
			return "", "", false, rerr
		}
		contractHTML := buildHTMLDocument(brandCSS, signedHTML, "")
		pdfBytes, err = e.PDF.HTMLToPDF(ctx, contractHTML, render.PDFOptions{WaitDelay: "1500ms"})
		if err != nil {
			return "", "", false, fmt.Errorf("gotenberg render: %w", err)
		}
	} else {
		original, lerr := e.loadSourcePDF(ctx, doc)
		if lerr != nil {
			return "", "", false, lerr
		}
		stamped, serr := e.stampFieldsAndSignatures(ctx, doc, original)
		if serr != nil {
			return "", "", false, fmt.Errorf("stamp pdf: %w", serr)
		}
		pdfBytes = stamped
	}

	artifactDir := path.Join("org", doc.OrgID.String(), "documents", doc.ID.String())
	finalSum := sha256.Sum256(pdfBytes)
	chainHead, err := e.Queries.LatestEventChainHeadForOrg(ctx, doc.OrgID)
	if err != nil {
		return "", "", false, fmt.Errorf("load pre-final audit chain head: %w", err)
	}
	documentEvents, err := e.loadCertificateDocumentEvents(ctx, doc.ID)
	if err != nil {
		return "", "", false, err
	}
	claims, err := newCertificateEvidenceClaims(doc, finalSum[:], chainHead, documentEvents)
	if err != nil {
		return "", "", false, err
	}
	finalKey = path.Join(artifactDir, "final-"+hex.EncodeToString(finalSum[:])+".pdf")
	storedFinal, err := e.Storage.PutEvidenceVersioned(ctx, finalKey, "application/pdf", pdfBytes, retainUntil)
	if err != nil {
		return "", "", false, fmt.Errorf("store final pdf: %w", err)
	}
	if storedFinal.SHA256 != finalSum || strings.TrimSpace(storedFinal.VersionID) == "" {
		return "", "", false, errors.New("store final pdf: storage digest mismatch")
	}
	certArtifacts, err := e.renderAndStoreAuditCertificate(ctx, doc, manifestHTML, claims, artifactDir, brandCSS, retainUntil)
	if err != nil {
		return "", "", false, err
	}
	staged := stagedDocumentFinalization{
		Mode: "signature", FinalKey: finalKey, FinalSHA256: finalSum,
		FinalVersionID: storedFinal.VersionID, Certificate: certArtifacts,
	}
	if err := e.beginDocumentFinalization(ctx, conn, doc, staged); err != nil {
		return "", "", false, err
	}
	completedDoc, did, err := e.resumeDocumentFinalization(ctx, conn, doc, capture)
	if err != nil || completedDoc == nil {
		return "", "", false, err
	}
	return completedDoc.FinalPdfKey.String, completedDoc.AuditCertKey.String, did, nil
}

// verifyCompletedEnvelopeChildren makes the terminal propagation all-or-none.
// CompleteEnvelopeChildren deliberately updates only children frozen to the
// root's exact completion and retention commitments. If any row diverges, the
// returned set differs and this transaction (including the parent completion)
// rolls back rather than certifying a bundle whose persisted rows disagree.
func verifyCompletedEnvelopeChildren(expected, completed []*generated.Document, completionEffectiveAt, retainUntil pgtype.Timestamptz, finalKey string, finalSHA []byte, finalVersionID string, cert storedAuditCertificate) error {
	if _, err := canonicalFinalizationRetainUntil(completionEffectiveAt, retainUntil); err != nil {
		return fmt.Errorf("complete envelope children: %w", err)
	}
	if len(expected) == 0 || len(completed) != len(expected) {
		return fmt.Errorf("complete envelope children: updated %d of %d children", len(completed), len(expected))
	}
	want := make(map[uuid.UUID]*generated.Document, len(expected))
	for _, child := range expected {
		if child == nil || child.Status != "finalizing" || !child.CompletionEffectiveAtBound ||
			!completionEffectiveTimesEqual(child.CompletionEffectiveAt, completionEffectiveAt) ||
			!retentionTimesEqual(child.FinalizationRetainUntil, retainUntil) {
			return errors.New("complete envelope children: expected child is not frozen to the envelope commitment")
		}
		want[child.ID] = child
	}
	for _, child := range completed {
		if child == nil {
			return errors.New("complete envelope children: returned nil child")
		}
		original, ok := want[child.ID]
		if !ok {
			return fmt.Errorf("complete envelope children: unexpected child %s", child.ID)
		}
		if child.Status != "completed" ||
			!child.CompletionEffectiveAtBound ||
			!completionEffectiveTimesEqual(child.CompletionEffectiveAt, completionEffectiveAt) ||
			!retentionTimesEqual(child.FinalizationRetainUntil, retainUntil) ||
			!completionEffectiveTimesEqual(child.CompletedAt, completionEffectiveAt) ||
			!child.FinalPdfKey.Valid || child.FinalPdfKey.String != finalKey ||
			!bytes.Equal(child.FinalPdfSha, finalSHA) || !child.FinalPdfVersionID.Valid || child.FinalPdfVersionID.String != finalVersionID ||
			!child.AuditCertKey.Valid || child.AuditCertKey.String != cert.CertKey ||
			!bytes.Equal(child.AuditCertSha256, cert.CertSHA256[:]) || !child.AuditCertVersionID.Valid || child.AuditCertVersionID.String != cert.CertVersionID ||
			!child.AuditPayloadKey.Valid || child.AuditPayloadKey.String != cert.PayloadKey ||
			!bytes.Equal(child.AuditPayloadSha256, cert.PayloadSHA256[:]) || !child.AuditPayloadVersionID.Valid || child.AuditPayloadVersionID.String != cert.PayloadVersionID ||
			!child.AuditSignatureKey.Valid || child.AuditSignatureKey.String != cert.SignatureKey ||
			!bytes.Equal(child.AuditSignatureSha256, cert.SignatureSHA256[:]) || !child.AuditSignatureVersionID.Valid || child.AuditSignatureVersionID.String != cert.SignatureVersionID ||
			!child.EvidenceVersionPinsRequired {
			return fmt.Errorf("complete envelope children: child %s terminal artifacts do not match envelope", child.ID)
		}
		if !bytes.Equal(child.BlocksJson, original.BlocksJson) || !bytes.Equal(child.VariablesJson, original.VariablesJson) {
			return fmt.Errorf("complete envelope children: child %s content changed during finalize", child.ID)
		}
		delete(want, child.ID)
	}
	if len(want) != 0 {
		return errors.New("complete envelope children: persisted child set is incomplete")
	}
	return nil
}

// renderFinalBlocksBody is the canonical blocks-source body for terminal PDF
// rendering. An envelope shell is intentionally empty, so rendering its own
// BlocksJson would produce a certificate-only PDF while the signer ceremony
// had shown every child. Finalization must use the same ordered child body as
// RenderForSigner and fail closed if envelope wiring is unavailable.
func (e *Engine) renderFinalBlocksBody(ctx context.Context, doc *generated.Document, locale string) (string, error) {
	if doc == nil {
		return "", errors.New("render final blocks body: nil document")
	}
	if doc.IsEnvelope {
		if e.EnvelopeChildren == nil {
			return "", errors.New("render final blocks body: envelope children unavailable")
		}
		return e.renderEnvelopeBody(ctx, doc, locale)
	}
	tree, vars, err := frozenBlockDocument(doc)
	if err != nil {
		return "", err
	}
	return e.renderSignedHTML(ctx, tree, doc.ID, vars, locale)
}

// advisoryLockKey derives a stable int64 from a document UUID for use as a
// Postgres advisory-lock key.
func advisoryLockKey(id uuid.UUID) int64 {
	return int64(binary.BigEndian.Uint64(id[:8]))
}

// findOrInsertFieldTx returns the document_fields row for a signature_field
// block, inserting a placeholder if none exists for this recipient + sig type.
// Runs through the supplied tx-scoped queries.
func (e *Engine) findOrInsertFieldTx(ctx context.Context, q *generated.Queries, doc *generated.Document, recID uuid.UUID, blockID string) (*generated.DocumentField, error) {
	_ = blockID
	if doc == nil {
		return nil, errors.New("signature field: nil document")
	}
	rows, err := q.ListFieldsByDocument(ctx, doc.ID)
	if err != nil {
		return nil, err
	}
	for _, f := range rows {
		if f.RecipientID.Valid && uuid.UUID(f.RecipientID.Bytes) == recID && f.Type == "signature" {
			return f, nil
		}
	}
	if !canMaterializeSignatureField(doc) {
		return nil, errors.New("PDF signature field is missing; sender must place and assign a visible signature field before send")
	}
	zero := pgtype.Numeric{Int: big.NewInt(0), Exp: 0, Valid: true}
	row, err := q.CreateField(ctx, generated.CreateFieldParams{
		DocumentID:  doc.ID,
		RecipientID: pgtype.UUID{Bytes: recID, Valid: true},
		Type:        "signature",
		Page:        1,
		// For block-source documents the coordinates are meaningless (the
		// signature is inlined into the HTML). Stored as zeros to satisfy
		// the NOT NULL constraint; week-4 PDF-stamp flows populate real
		// values from the post-render coordinate-extraction pass.
		XPct:        zero,
		YPct:        zero,
		WPct:        zero,
		HPct:        zero,
		Required:    true,
		Label:       pgtype.Text{String: "Signature", Valid: true},
		OptionsJson: []byte(`{}`),
	})
	return row, err
}

func canMaterializeSignatureField(doc *generated.Document) bool {
	return doc != nil && doc.SourceKind == "blocks"
}

// signerRolesForDoc is the boolean-only compatibility helper used by pure
// readiness predicates. Block documents derive roles solely from signature
// fields present after projecting the frozen conditional tree; PDF documents
// use the canonical legacy signer role. Invalid block state returns no roles
// and therefore cannot satisfy readiness.
func signerRolesForDoc(doc *generated.Document) []string {
	if doc == nil {
		return nil
	}
	if doc.SourceKind != "blocks" {
		return []string{"signer"}
	}
	roles, err := projectedBlockSignerRoles(doc)
	if err != nil {
		return nil
	}
	return roles
}

func projectedBlockSignerRoles(doc *generated.Document) ([]string, error) {
	if doc == nil || doc.SourceKind != "blocks" {
		return nil, errors.New("resolve signer roles: blocks document required")
	}
	tree, values, err := frozenBlockDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("resolve signer roles: %w", err)
	}
	roles, err := blocks.RequiredSignerRolesForVariables(tree, values)
	if err != nil {
		return nil, fmt.Errorf("resolve signer roles: project conditions: %w", err)
	}
	if len(roles) == 0 {
		return nil, errors.New("resolve signer roles: document contains no active signature fields")
	}
	return roles, nil
}

// signerRolesForDocument is the fail-closed, envelope-aware role resolver used
// at every signing terminal boundary. The legacy pure helper above remains for
// ordinary documents and unit tests; envelopes have an intentionally empty
// shell, so their required roles must be gathered from every frozen child.
func (e *Engine) signerRolesForDocument(ctx context.Context, doc *generated.Document) ([]string, error) {
	if doc == nil {
		return nil, errors.New("resolve signer roles: nil document")
	}
	if !doc.IsEnvelope {
		if doc.SourceKind == "blocks" {
			return projectedBlockSignerRoles(doc)
		}
		return []string{"signer"}, nil
	}
	if e.EnvelopeChildren == nil {
		return nil, errors.New("resolve signer roles: envelope children unavailable")
	}
	children, err := e.EnvelopeChildren(ctx, doc)
	if err != nil {
		return nil, fmt.Errorf("resolve signer roles: list envelope children: %w", err)
	}
	if len(children) == 0 {
		return nil, errors.New("resolve signer roles: envelope has no children")
	}
	roles := map[string]struct{}{}
	for i, child := range children {
		if child == nil {
			return nil, fmt.Errorf("resolve signer roles: child %d is nil", i+1)
		}
		if !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != doc.ID {
			return nil, fmt.Errorf("resolve signer roles: child %s is not attached", child.ID)
		}
		if child.IsEnvelope {
			return nil, fmt.Errorf("resolve signer roles: child %s is itself an envelope", child.ID)
		}
		if doc.Status == "completed" {
			if child.Status != "completed" {
				return nil, fmt.Errorf("resolve signer roles: child %s is not completed", child.ID)
			}
		} else if !envelopeChildStatusMatchesParent(doc.Status, child.Status) {
			return nil, fmt.Errorf("resolve signer roles: child %s status %s does not match envelope status %s", child.ID, child.Status, doc.Status)
		}
		if doc.Status == "finalizing" {
			if err := validateFinalizingEnvelopeRoleCommitment(doc, child); err != nil {
				return nil, fmt.Errorf("resolve signer roles: child %s: %w", child.ID, err)
			}
		}
		if child.SourceKind != "blocks" {
			return nil, fmt.Errorf("resolve signer roles: child %s is not a blocks document", child.ID)
		}
		childRoles, err := projectedBlockSignerRoles(child)
		if err != nil {
			return nil, fmt.Errorf("resolve signer roles: child %s: %w", child.ID, err)
		}
		for _, role := range childRoles {
			roles[role] = struct{}{}
		}
	}
	if len(roles) == 0 {
		return nil, errors.New("resolve signer roles: envelope children contain no signature fields")
	}
	out := make([]string, 0, len(roles))
	for role := range roles {
		out = append(out, role)
	}
	sort.Strings(out)
	return out, nil
}

// validateFinalizingEnvelopeRoleCommitment prevents the role recheck from
// accepting a merely-finalizing child from another or partially applied family
// transition. The root and every child must carry the same canonical completion
// instant and retention deadline allocated by the atomic family freeze.
func validateFinalizingEnvelopeRoleCommitment(parent, child *generated.Document) error {
	if parent == nil || child == nil || parent.Status != "finalizing" || child.Status != "finalizing" {
		return errors.New("finalizing envelope family is required")
	}
	if !parent.CompletionEffectiveAtBound || !child.CompletionEffectiveAtBound {
		return errors.New("completion-effective timestamp is not bound across the envelope family")
	}
	if _, err := canonicalFinalizationRetainUntil(parent.CompletionEffectiveAt, parent.FinalizationRetainUntil); err != nil {
		return fmt.Errorf("envelope commitment: %w", err)
	}
	if _, err := canonicalFinalizationRetainUntil(child.CompletionEffectiveAt, child.FinalizationRetainUntil); err != nil {
		return fmt.Errorf("child commitment: %w", err)
	}
	if !completionEffectiveTimesEqual(parent.CompletionEffectiveAt, child.CompletionEffectiveAt) {
		return errors.New("completion-effective timestamp differs from the envelope")
	}
	if !retentionTimesEqual(parent.FinalizationRetainUntil, child.FinalizationRetainUntil) {
		return errors.New("retention deadline differs from the envelope")
	}
	return nil
}

func signerRoleSet(roles []string) map[string]struct{} {
	out := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		if role != "" {
			out[role] = struct{}{}
		}
	}
	return out
}

func requiredSignerRoleSet(doc *generated.Document) map[string]struct{} {
	roles := signerRolesForDoc(doc)
	out := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		out[role] = struct{}{}
	}
	return out
}

// allRequiredRecipientsSigned is the shared readiness predicate used by the
// terminal finalizer and retry worker. Every recipient in a required role must
// be signed, and every required role must have at least one recipient. Treating
// declined/corrupt states as incomplete is deliberately stricter than the old
// count query; a normal decline has already made the document terminal anyway.
func allRequiredRecipientsSigned(doc *generated.Document, recipients []*generated.Recipient) bool {
	return allRequiredRecipientsSignedForRoles(signerRolesForDoc(doc), recipients)
}

func allRequiredRecipientsSignedForRoles(roles []string, recipients []*generated.Recipient) bool {
	required := signerRoleSet(roles)
	seen := make(map[string]bool, len(required))
	for _, rec := range recipients {
		if rec == nil {
			continue
		}
		if _, ok := required[rec.Role]; !ok {
			continue
		}
		seen[rec.Role] = true
		if rec.Status != "signed" {
			return false
		}
	}
	for role := range required {
		if !seen[role] {
			return false
		}
	}
	return len(required) > 0
}

// allRequiredAcceptorsAccepted mirrors CountPendingAcceptors for retry safety,
// while requiring at least one non-cc recipient so a malformed cc-only
// acknowledgement cannot become completed merely because its required set is
// empty.
func allRequiredAcceptorsAccepted(recipients []*generated.Recipient) bool {
	found := false
	for _, rec := range recipients {
		if rec == nil || rec.Role == "cc" {
			continue
		}
		found = true
		if rec.Status != "accepted" {
			return false
		}
	}
	return found
}

func recipientReceivesSenderComment(recipient *generated.Recipient) bool {
	return recipient != nil && recipients.CanRespond(recipient.Role)
}

func findSignatureFieldFor(t *blocks.Tree, role string) *blocks.Block {
	if t == nil {
		return nil
	}
	return findSignatureFieldInBlocks(t.Blocks, role)
}

func findSignatureFieldInBlocks(bs []blocks.Block, role string) *blocks.Block {
	for i := range bs {
		b := &bs[i]
		if b.Type == blocks.TypeSignatureField {
			want := b.AttrString("recipient_role", "")
			if want == "" {
				want = "signer"
			}
			if want == role {
				return b
			}
		}
		if found := findSignatureFieldInBlocks(b.Content, role); found != nil {
			return found
		}
	}
	return nil
}

func findActiveSignatureFieldFor(t *blocks.Tree, role string, vars map[string]string) (*blocks.Block, error) {
	if t == nil {
		return nil, nil
	}
	var visit func([]blocks.Block) (*blocks.Block, error)
	visit = func(items []blocks.Block) (*blocks.Block, error) {
		for i := range items {
			block := &items[i]
			if block.Type == blocks.TypeConditional {
				included, err := blocks.EvalConditionStrict(block.AttrString("expression", ""), vars)
				if err != nil {
					return nil, err
				}
				if !included {
					continue
				}
			}
			if block.Type == blocks.TypeSignatureField {
				want := block.AttrString("recipient_role", "")
				if want == "" {
					want = "signer"
				}
				if want == role {
					return block, nil
				}
			}
			found, err := visit(block.Content)
			if err != nil || found != nil {
				return found, err
			}
		}
		return nil, nil
	}
	return visit(t.Blocks)
}

func frozenBlockDocument(doc *generated.Document) (*blocks.Tree, map[string]string, error) {
	if doc == nil || doc.SourceKind != "blocks" {
		return nil, nil, errors.New("frozen blocks document required")
	}
	tree, err := blocks.ParseCanonicalTree(doc.BlocksJson)
	if err != nil {
		return nil, nil, fmt.Errorf("parse block tree: %w", err)
	}
	values, err := blocks.ValidateResolvedVariableValues(tree, doc.VariablesJson)
	if err != nil {
		return nil, nil, fmt.Errorf("validate frozen variables: %w", err)
	}
	return tree, values, nil
}

func (e *Engine) validateFrozenDocumentFamily(ctx context.Context, doc *generated.Document) error {
	if doc == nil {
		return errors.New("validate frozen evidence: nil document")
	}
	if !doc.IsEnvelope {
		if doc.SourceKind != "blocks" {
			return nil
		}
		_, _, err := frozenBlockDocument(doc)
		return err
	}
	if e.EnvelopeChildren == nil {
		return errors.New("validate frozen evidence: envelope children unavailable")
	}
	children, err := e.EnvelopeChildren(ctx, doc)
	if err != nil {
		return fmt.Errorf("validate frozen evidence: list envelope children: %w", err)
	}
	if len(children) == 0 {
		return errors.New("validate frozen evidence: envelope has no children")
	}
	for i, child := range children {
		if child == nil {
			return fmt.Errorf("validate frozen evidence: child %d is nil", i+1)
		}
		if !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != doc.ID {
			return fmt.Errorf("validate frozen evidence: child %s is not attached", child.ID)
		}
		if !envelopeChildStatusMatchesParent(doc.Status, child.Status) {
			return fmt.Errorf("validate frozen evidence: child %s status %s does not match envelope status %s", child.ID, child.Status, doc.Status)
		}
		if _, _, err := frozenBlockDocument(child); err != nil {
			return fmt.Errorf("validate frozen evidence: child %s: %w", child.ID, err)
		}
	}
	return nil
}

func envelopeChildStatusMatchesParent(parentStatus, childStatus string) bool {
	if parentStatus == "finalizing" {
		return childStatus == "finalizing"
	}
	switch parentStatus {
	case "sent", "in_progress", "changes_requested":
		return childStatus == "sent" || childStatus == "in_progress"
	default:
		return false
	}
}

// renderSignedHTML walks the tree, replacing signature_field blocks with
// the recipient's signed signature span when one exists.
func (e *Engine) renderSignedHTML(ctx context.Context, tree *blocks.Tree, docID uuid.UUID, vars map[string]string, locale string) (string, error) {
	var sigs []*generated.Signature
	if e.Queries != nil {
		// Nil-Queries is allowed in unit tests that exercise the
		// rendering path without standing up a sql backend; in that
		// mode we skip signature inlining + render only the static
		// content.
		var err error
		sigs, err = e.Queries.ListSignaturesByDocument(ctx, docID)
		if err != nil {
			return "", err
		}
	}
	spanBySigner := map[string]string{}
	for _, s := range sigs {
		span, err := render.RenderSignatureSpan(s.TypedName, s.Font)
		if err != nil {
			return "", fmt.Errorf("render stored signature %s: %w", s.ID, err)
		}
		spanBySigner[s.RecipientID.String()] = span
	}
	var recs []*generated.Recipient
	if e.Queries != nil {
		var err error
		recs, err = e.Queries.ListRecipientsByDocument(ctx, docID)
		if err != nil {
			return "", err
		}
	}

	var replaceFields func([]blocks.Block)
	replaceFields = func(bs []blocks.Block) {
		for i := range bs {
			b := &bs[i]
			if b.Type == blocks.TypeSignatureField {
				role := b.AttrString("recipient_role", "")
				if role == "" {
					role = "signer"
				}
				var signedSpan string
				for _, rec := range recs {
					if rec.Role != role {
						continue
					}
					if span, ok := spanBySigner[rec.ID.String()]; ok {
						signedSpan = span
						break
					}
				}
				if signedSpan == "" {
					signedSpan = `<span class="hash-field--unsigned">` + htmlEscape(i18n.T(i18n.Normalize(locale), "sign.signaturePending", nil)) + `</span>`
				} else {
					signedSpan = `<span class="hash-field--signed">` + signedSpan + `</span>`
				}
				b.Type = blocks.TypeRawHTML
				b.Text = signedSpan
				b.Attrs = nil
			}
			replaceFields(b.Content)
		}
	}
	replaceFields(tree.Blocks)
	return blocks.RenderHTML(tree, vars), nil
}

// renderAuditCertificateWithManifest accepts the terminal envelope manifest
// generated from the exact frozen child snapshot being rendered. A nil override
// keeps the legacy callback for non-final preview callers; envelope finalize
// always supplies a non-empty override and therefore never signs pre-terminal
// child status or empty/circular final-PDF hashes.
func (e *Engine) renderAuditCertificateWithManifest(ctx context.Context, doc *generated.Document, manifestHTML *string, claims certificateEvidenceClaims) (html, signedPayload, signature string, err error) {
	if e.Signer == nil {
		return "", "", "", errors.New("audit certificate: signer unavailable")
	}
	recs, err := e.Queries.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil {
		return "", "", "", err
	}
	sigs, err := e.Queries.ListSignaturesByDocument(ctx, doc.ID)
	if err != nil {
		return "", "", "", err
	}
	sigByRec := map[string]*generated.Signature{}
	for _, s := range sigs {
		sigByRec[s.RecipientID.String()] = s
	}

	var sb strings.Builder
	sb.WriteString(`<div class="hash-cert-page">`)
	sb.WriteString(`<h2>Audit Certificate</h2>`)
	fmt.Fprintf(&sb, `<p><strong>Document:</strong> %s</p>`, htmlEscape(doc.Name))
	fmt.Fprintf(&sb, `<p><strong>Document ID:</strong> %s</p>`, doc.ID)
	fmt.Fprintf(&sb, `<p><strong>Sent at:</strong> %s</p>`, formatNullableTS(doc.SentAt))
	if !doc.CompletionEffectiveAtBound {
		return "", "", "", errors.New("audit certificate: completion-effective timestamp is not bound for this ceremony")
	}
	completionEffectiveAt, err := canonicalCompletionEffectiveAt(doc.CompletionEffectiveAt)
	if err != nil {
		return "", "", "", fmt.Errorf("audit certificate: %w", err)
	}
	if claims.CompletionEffectiveAt != completionEffectiveAt {
		return "", "", "", errors.New("audit certificate: completion-effective timestamp claim does not match document")
	}
	fmt.Fprintf(&sb, `<p><strong>Completion effective at:</strong> %s</p>`, htmlEscape(completionEffectiveAt))

	sb.WriteString(`<table><thead><tr><th>Role</th><th>Recipient</th><th>Status</th><th>Signed at</th><th>Font</th><th>Image SHA-256</th></tr></thead><tbody>`)
	for _, rec := range recs {
		var sig *generated.Signature
		if s, ok := sigByRec[rec.ID.String()]; ok {
			sig = s
		}
		fmt.Fprintf(&sb,
			`<tr><td>%s</td><td>%s &lt;%s&gt;</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			htmlEscape(rec.Role),
			htmlEscape(rec.Name),
			htmlEscape(rec.Email),
			htmlEscape(rec.Status),
			formatNullableTS(rec.SignedAt),
			signatureFontOrNA(sig),
			signatureSHAOrNA(sig),
		)
	}
	sb.WriteString(`</tbody></table>`)

	// v1.2: surface every filled non-signature field (text/date/checkbox/
	// dropdown/initial) so the audit cert binds the structured signer
	// inputs alongside the typed-name signatures. Empty rendering when
	// no fields were filled keeps unchanged docs identical to pre-v1.2.
	if section := renderFieldValuesSection(ctx, e.Queries, doc.ID); section != "" {
		sb.WriteString(section)
	}

	// Bind the exact final contract body and a pre-final prefix of the
	// immutable org audit ledger. These machine-readable claims are inside the
	// detached signed payload, not merely in the later unsigned export manifest.
	sb.WriteString(claims.HTML())

	// Append the content-snapshot manifest BEFORE signing so the detached
	// ed25519 signature binds every frozen child body without a final-PDF
	// self-hash cycle.
	if manifestHTML != nil {
		if *manifestHTML == "" {
			return "", "", "", errors.New("audit certificate: empty envelope manifest override")
		}
		sb.WriteString(*manifestHTML)
	} else if e.EnvelopeManifestHTML != nil {
		if section := e.EnvelopeManifestHTML(ctx, doc); section != "" {
			sb.WriteString(section)
		}
	}

	// Phase 8.7: surface the metadata-redaction report so signers + court
	// reviewers can see what PII the sanitizer stripped at upload time.
	// Embedded before the ed25519 signature so the signature covers the
	// report (a tampered report changes the cert payload and breaks
	// verification). Empty / no-items reports emit nothing so unmigrated
	// documents render unchanged.
	if section := renderRedactionReportSection(doc.MetadataRedactionReport); section != "" {
		sb.WriteString(section)
	}

	// Bind everything we just rendered into a single signed payload so
	// anyone can verify the cert offline against the published public key.
	signedPayload = sb.String()
	signature = e.Signer.SignPayload([]byte(signedPayload))
	if signature == "" {
		return "", "", "", errors.New("audit certificate: signer returned an empty signature")
	}
	issuer := strings.TrimSpace(e.OrgName)
	if issuer == "" {
		issuer = "Hash"
	}
	verifyURL := strings.TrimRight(strings.TrimSpace(e.BaseURL), "/") + "/verify"
	fmt.Fprintf(&sb, `<div style="margin-top:24px;padding:12px;border:1px solid #ddd;background:#fafafa;font-family:monospace;font-size:9px;line-height:1.5;">
<div><strong>Issuer:</strong> Hash / %s</div>
<div><strong>Public key (ed25519, base64):</strong> %s</div>
<div><strong>Signature (ed25519 over SHA-256(domain ‖ cert)):</strong> %s</div>
<div style="color:#666;margin-top:6px">Server-assisted verification (uploads certificate data): %s</div>
</div>`,
		htmlEscape(issuer),
		htmlEscape(e.Signer.PublicKeyBase64()),
		htmlEscape(signature),
		htmlEscape(verifyURL))
	sb.WriteString(`</div>`)
	return sb.String(), signedPayload, signature, nil
}

// renderAndStoreAuditCertificate persists the visible certificate plus the
// exact signed payload and detached signature under digest-addressed immutable
// keys. Both signature and acknowledgement ceremonies use this same path.
type storedAuditCertificate struct {
	CertKey            string
	CertSHA256         [sha256.Size]byte
	CertVersionID      string
	PayloadKey         string
	PayloadSHA256      [sha256.Size]byte
	PayloadVersionID   string
	SignatureKey       string
	SignatureSHA256    [sha256.Size]byte
	SignatureVersionID string
}

func (e *Engine) renderAndStoreAuditCertificate(ctx context.Context, doc *generated.Document, manifestHTML *string, claims certificateEvidenceClaims, artifactDir, brandCSS string, retainUntil time.Time) (storedAuditCertificate, error) {
	cert, certPayload, certSignature, err := e.renderAuditCertificateWithManifest(ctx, doc, manifestHTML, claims)
	if err != nil {
		return storedAuditCertificate{}, err
	}
	if certPayload == "" || certSignature == "" {
		return storedAuditCertificate{}, errors.New("audit certificate: detached evidence is incomplete")
	}
	certHTML := buildHTMLDocument(brandCSS, "", cert)
	certBytes, err := e.PDF.HTMLToPDF(ctx, certHTML, render.PDFOptions{})
	if err != nil {
		return storedAuditCertificate{}, fmt.Errorf("gotenberg render cert: %w", err)
	}
	certSum := sha256.Sum256(certBytes)
	certBase := "audit-" + hex.EncodeToString(certSum[:])
	certKey := path.Join(artifactDir, certBase+".pdf")
	storedCert, err := e.Storage.PutEvidenceVersioned(ctx, certKey, "application/pdf", certBytes, retainUntil)
	if err != nil {
		return storedAuditCertificate{}, fmt.Errorf("store cert pdf: %w", err)
	}
	if storedCert.SHA256 != certSum || strings.TrimSpace(storedCert.VersionID) == "" {
		return storedAuditCertificate{}, errors.New("store cert pdf: storage digest mismatch")
	}
	payloadBytes := []byte(certPayload)
	payloadSum := sha256.Sum256(payloadBytes)
	payloadKey := path.Join(artifactDir, "audit-payload-"+hex.EncodeToString(payloadSum[:])+".txt")
	storedPayload, err := e.Storage.PutEvidenceVersioned(ctx, payloadKey, "text/html; charset=utf-8", payloadBytes, retainUntil)
	if err != nil {
		return storedAuditCertificate{}, fmt.Errorf("store cert payload: %w", err)
	}
	if storedPayload.SHA256 != payloadSum || strings.TrimSpace(storedPayload.VersionID) == "" {
		return storedAuditCertificate{}, errors.New("store cert payload: storage digest mismatch")
	}
	signatureBytes := []byte(certSignature)
	signatureSum := sha256.Sum256(signatureBytes)
	signatureKey := path.Join(artifactDir, "audit-signature-"+hex.EncodeToString(signatureSum[:])+".txt")
	storedSignature, err := e.Storage.PutEvidenceVersioned(ctx, signatureKey, "text/plain; charset=utf-8", signatureBytes, retainUntil)
	if err != nil {
		return storedAuditCertificate{}, fmt.Errorf("store cert signature: %w", err)
	}
	if storedSignature.SHA256 != signatureSum || strings.TrimSpace(storedSignature.VersionID) == "" {
		return storedAuditCertificate{}, errors.New("store cert signature: storage digest mismatch")
	}
	return storedAuditCertificate{
		CertKey: certKey, CertSHA256: certSum, CertVersionID: storedCert.VersionID,
		PayloadKey: payloadKey, PayloadSHA256: payloadSum, PayloadVersionID: storedPayload.VersionID,
		SignatureKey: signatureKey, SignatureSHA256: signatureSum, SignatureVersionID: storedSignature.VersionID,
	}, nil
}

func (e *Engine) loadCertificateDocumentEvents(ctx context.Context, docID uuid.UUID) ([]*generated.Event, error) {
	events, err := e.Queries.ListEventsByDocument(ctx, generated.ListEventsByDocumentParams{
		DocumentID: pgtype.UUID{Bytes: docID, Valid: true},
		Limit:      maxCertificateDocumentEvents + 1,
	})
	if err != nil {
		return nil, fmt.Errorf("audit certificate: load pre-final document events: %w", err)
	}
	if len(events) > maxCertificateDocumentEvents {
		return nil, fmt.Errorf("audit certificate: document has more than %d pre-final events", maxCertificateDocumentEvents)
	}
	return events, nil
}

func signatureFontOrNA(s *generated.Signature) string {
	if s == nil {
		return ", "
	}
	return htmlEscape(s.Font)
}

func signatureSHAOrNA(s *generated.Signature) string {
	if s == nil {
		return ", "
	}
	return fmt.Sprintf("<code>%x</code>", s.ImageSha256)
}

func formatNullableTS(t pgtype.Timestamptz) string {
	if !t.Valid {
		return ", "
	}
	return t.Time.UTC().Format(time.RFC3339)
}

// renderFieldValuesSection produces a "Filled fields" table for the
// audit cert. Only non-signature fields with a populated value are
// listed; the signature path already gets its own rows in the
// recipients table above. Empty / no-fields docs return "" so unchanged
// documents render byte-identical to pre-v1.2 certs.
//
// Each row carries the field label, type, page, value, and the
// completed_at timestamp. Values are HTML-escaped so a malicious signer
// can't inject markup into the cert; long values are truncated at 200
// chars with an indicator so the cert stays readable on a printed page.
func renderFieldValuesSection(ctx context.Context, q *generated.Queries, docID uuid.UUID) string {
	if q == nil {
		return ""
	}
	rows, err := q.ListFieldsByDocument(ctx, docID)
	if err != nil {
		return ""
	}
	var visible []*generated.DocumentField
	for _, f := range rows {
		switch f.Type {
		case "text", "date", "checkbox", "dropdown", "initial":
		default:
			continue
		}
		if !f.Value.Valid || f.Value.String == "" {
			continue
		}
		visible = append(visible, f)
	}
	if len(visible) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<h3 style="margin-top:24px">Filled fields</h3>`)
	sb.WriteString(`<table><thead><tr><th>Label</th><th>Type</th><th>Page</th><th>Value</th><th>Filled at</th></tr></thead><tbody>`)
	for _, f := range visible {
		label := ""
		if f.Label.Valid {
			label = f.Label.String
		}
		fmt.Fprintf(&sb,
			`<tr><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td></tr>`,
			htmlEscape(label),
			htmlEscape(f.Type),
			f.Page,
			htmlEscape(truncateFieldValueForCert(f.Value.String)),
			formatNullableTS(f.CompletedAt),
		)
	}
	sb.WriteString(`</tbody></table>`)
	return sb.String()
}

// truncateFieldValueForCert caps a value at 200 chars with a marker so
// a malicious or accidentally-huge submission doesn't blow the cert
// page out. The full value lives in document_fields.value; the cert is
// a forensic summary, not the system of record.
func truncateFieldValueForCert(v string) string {
	const max = 200
	if utf8.RuneCountInString(v) <= max {
		return v
	}
	return string([]rune(v)[:max]) + "… [truncated, full value in document_fields]"
}

func buildHTMLDocument(brandCSS, body, cert string) string {
	// Branding CSS is emitted FIRST so its custom properties on :root are
	// available to the base stylesheet's rules below. The base styles use
	// var(--hash-text) etc. with safe fallbacks so an unconfigured
	// org still renders with the system defaults.
	// Layout note: every visible rule is scoped under .hash-doc so injecting
	// this whole document into the signer SPA via {@html} can't leak typography
	// onto the app chrome. The content lives in a centered, fixed-measure column
	// (Google-Docs feel); page geometry/margins are set by Gotenberg on render.
	return fmt.Sprintf(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8" />
%s
<style>
  * { box-sizing: border-box; }
  body { margin: 0; }
  .hash-doc { max-width: 46rem; margin: 0 auto; font-family: var(--hash-font-body, Inter), system-ui, -apple-system, sans-serif; font-size: 11.5px; line-height: 1.65; color: var(--hash-text, #18181b); }
  .hash-doc__rule { height: 3px; border-radius: 2px; background: var(--hash-accent, #0891B2); margin: 0 0 26px; }
  .hash-doc h1 { font-family: var(--hash-font-heading, Geist), sans-serif; font-weight: 600; font-size: 24px; line-height: 1.2; letter-spacing: -0.01em; margin: 6px 0 14px; color: var(--hash-primary, #18181b); }
  .hash-doc h2 { font-family: var(--hash-font-heading, Geist), sans-serif; font-weight: 600; font-size: 14.5px; margin: 22px 0 9px; padding-left: 11px; border-left: 3px solid var(--hash-accent, #0891B2); color: var(--hash-primary, #18181b); }
  .hash-doc h3 { font-family: var(--hash-font-heading, Geist), sans-serif; font-weight: 600; font-size: 12.5px; margin: 16px 0 6px; color: var(--hash-primary, #18181b); }
  .hash-doc p { margin: 8px 0; }
  /* Pagination: keep each section (heading + its content) whole; if it would be
     cut by a page edge, move it to the next page instead of splitting it. */
  .hash-doc .doc-section { break-inside: avoid; page-break-inside: avoid; margin: 0 0 12px; }
  .hash-doc .doc-section:first-child { margin-top: 0; }
  .hash-doc a { color: var(--hash-accent, #0891B2); }
  .hash-doc ul, .hash-doc ol { margin: 9px 0; padding-left: 22px; }
  .hash-doc li { margin: 5px 0; }
  .hash-doc strong { font-weight: 600; color: var(--hash-primary, #18181b); }
  .hash-doc table { border-collapse: collapse; width: 100%%; margin: 10px 0; break-inside: auto; }
  .hash-doc th, .hash-doc td { padding: 6px 9px; border-bottom: 1px solid #e7e5e4; text-align: left; vertical-align: top; }
  .hash-doc th { font-size: 8.5px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--hash-muted, #52525b); }
  /* A table may span pages, but never split a row; repeat the header on each page. */
  .hash-doc thead { display: table-header-group; }
  .hash-doc tr, .hash-doc th, .hash-doc td { break-inside: avoid; page-break-inside: avoid; }
  .hash-doc hr { border: 0; border-top: 1px solid #e7e5e4; margin: 16px 0; }
  .hash-doc p, .hash-doc li, .hash-doc blockquote { break-inside: avoid; page-break-inside: avoid; }
  .hash-doc h1, .hash-doc h2, .hash-doc h3 { break-after: avoid; page-break-after: avoid; }
  .hash-doc blockquote { margin: 12px 0; padding: 11px 16px; border-left: 3px solid var(--hash-accent, #0891B2); background: rgba(8,145,178,0.06); color: var(--hash-text, #18181b); border-radius: 0 7px 7px 0; }
  .hash-doc blockquote p { margin: 0; }
  .hash-doc pre { background: #f5f5f4; border: 1px solid #e7e5e4; border-radius: 6px; padding: 10px; font-size: 11px; overflow-x: auto; }
  .hash-doc img { max-width: 100%%; }
  %s
  .hash-field--signed { display: inline-block; min-width: 340px; border-bottom: 1.5px solid var(--hash-primary, #18181b); padding: 0.15em 0.4em 0.3em; background: transparent; }
  .hash-field--unsigned { display: inline-block; min-width: 340px; border-bottom: 1.5px dashed var(--hash-accent, #0891B2); padding: 0.5em 0.4em; color: var(--hash-muted, #52525b); font-style: italic; }
</style>
</head><body>
<div class="hash-doc">
<div class="hash-doc__rule"></div>
%s
%s
</div>
</body></html>`, brandCSS, render.SignatureCSS(), body, cert)
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

func textOrNull(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}
