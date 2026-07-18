// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package sign owns the document signing state machine and the orchestration
// that turns a recipient's "I sign with this name in this font" click into
// a stamped, hashed final PDF.
package sign

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brightinteraction/hash/internal/actiontoken"
	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/blocks"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/dispatch"
	"github.com/brightinteraction/hash/internal/i18n"
	"github.com/brightinteraction/hash/internal/render"
	"github.com/brightinteraction/hash/internal/storage"
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
	// ErrFinalizeInProgress is returned when another worker/request already
	// holds the per-document finalize lock; the caller should treat the
	// signature as captured and let the in-flight finalize complete.
	ErrFinalizeInProgress = errors.New("finalize already in progress for this document")
	// ErrNotRevisable is returned when a revise targets a document that is not
	// paused in the changes_requested state.
	ErrNotRevisable = errors.New("document is not awaiting revision")
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
)

// Engine ties together the dependencies the signing flow needs.
type Engine struct {
	// Pool backs the transactional sign/decline/finalize path: row locks
	// (SELECT ... FOR UPDATE) and the per-document finalize advisory lock.
	Pool    *pgxpool.Pool
	Queries *generated.Queries
	Storage *storage.Client
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

// SignInput is what the signer page POSTs when they finalize.
type SignInput struct {
	TypedName string
	Font      string
	IP        string
	UserAgent string
}

// Result returned to the signer page on success.
type Result struct {
	DocumentID  uuid.UUID
	Status      string
	Completed   bool
	FinalPDFKey string
}

// RecipientContext bundles the verified recipient row with the parent
// document. The signer-side handler builds it after verifying the magic
// link, then passes it to Sign / Decline / MarkViewed so the engine never
// re-validates auth.
type RecipientContext struct {
	Recipient *generated.GetRecipientByTokenHashRow
	Document  *generated.Document
}

// ErrMagicLinkExpired is returned by LookupByToken when the recipient's
// magic_token_expires_at or the parent document's expires_at is in the
// past. Handlers surface this as 410 Gone to distinguish a deliberate
// TTL miss from a forged or revoked token (404).
var ErrMagicLinkExpired = errors.New("magic link expired")

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
	return &RecipientContext{Recipient: row, Document: doc}, nil
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
	if strings.TrimSpace(in.TypedName) == "" {
		return nil, errors.New("signer must type a name")
	}

	doc := rc.Document
	rec := rc.Recipient

	// Render + store the signature span to object storage BEFORE the tx so no
	// external I/O happens inside the lock window. The key is random, so two
	// concurrent attempts never clobber.
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
	if lockedDoc.Status != "sent" && lockedDoc.Status != "in_progress" {
		return nil, ErrDocumentNotSignable
	}
	freshRec, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: rec.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, err
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
	if unfilled, ferr := q.CountUnfilledRequiredForRecipient(ctx, generated.CountUnfilledRequiredForRecipientParams{
		DocumentID:  doc.ID,
		RecipientID: pgtype.UUID{Bytes: rec.ID, Valid: true},
	}); ferr == nil && unfilled > 0 {
		return nil, fmt.Errorf("%d required field(s) unfilled", unfilled)
	}

	sig, err := e.insertSignatureRow(ctx, q, doc, rec.ID, rec.Role, prep, in)
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
		Roles:      signerRolesForDoc(lockedDoc),
	})
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit signature: %w", err)
	}

	// Post-commit audit (the row is now durable). Webhook fan-out rides the
	// audit.Logger hook (cmd/server/main.go); no manual enqueue here.
	_, _ = e.Audit.Log(ctx, audit.Entry{
		OrgID: doc.OrgID, DocumentID: &doc.ID, RecipientID: &rec.ID,
		Kind:      audit.KindDocumentSigned,
		IP:        in.IP,
		UserAgent: in.UserAgent,
		Payload: map[string]any{
			"font":         in.Font,
			"typed_name":   in.TypedName,
			"image_sha256": fmt.Sprintf("%x", sig.ImageSha256),
			"signature_id": sig.ID,
		},
	})

	if remaining > 0 {
		return &Result{DocumentID: doc.ID, Status: "in_progress", Completed: false}, nil
	}

	// Last signer: finalize. The signature is already committed, so a finalize
	// failure no longer strands the document - the finalize-retry worker picks
	// it up. We therefore report "signed, finalizing" rather than failing the
	// signer's request.
	finalKey, certKey, did, ferr := e.finalize(ctx, doc.OrgID, doc.ID)
	if ferr != nil {
		// ErrFinalizeInProgress (another finalize holds the lock) and
		// ErrDocumentRevisedDuringFinalize (revised/voided under us) are
		// expected concurrency outcomes, not sign errors: the signature is
		// captured and the document stays non-completed.
		if !errors.Is(ferr, ErrFinalizeInProgress) && !errors.Is(ferr, ErrDocumentRevisedDuringFinalize) {
			_, _ = e.Audit.Log(ctx, audit.Entry{
				OrgID:      doc.OrgID,
				DocumentID: &doc.ID,
				Kind:       "sign.error",
				Payload:    map[string]any{"err": ferr.Error(), "phase": "finalize"},
			})
		}
		return &Result{DocumentID: doc.ID, Status: "in_progress", Completed: false}, nil
	}
	if did {
		e.afterFinalize(ctx, doc, finalKey, certKey)
	}
	return &Result{DocumentID: doc.ID, Status: "completed", Completed: true, FinalPDFKey: finalKey}, nil
}

// Accept records a recipient's acknowledgement of a NO-SIGNATURE document
// (requires_signature = false). It is the acknowledgement-mode twin of Sign:
// no signature image, no ed25519 seal, no audit cert. The tamper-evident proof
// is the event hash chain (the document.accepted + document.completed events).
// When every acceptor has accepted, the document completes with the original
// upload as its final PDF. The sealed finalize path is never touched.
func (e *Engine) Accept(ctx context.Context, rc *RecipientContext, ip, ua string) (*Result, error) {
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
	if lockedDoc.RequiresSignature {
		return nil, ErrNotAcknowledgement
	}
	if lockedDoc.Status != "sent" && lockedDoc.Status != "in_progress" {
		return nil, ErrDocumentNotSignable
	}
	freshRec, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: rec.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, err
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
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit accept: %w", err)
	}

	_, _ = e.Audit.Log(ctx, audit.Entry{
		OrgID: doc.OrgID, DocumentID: &doc.ID, RecipientID: &rec.ID,
		Kind:      audit.KindDocumentAccepted,
		IP:        ip,
		UserAgent: ua,
		Payload:   map[string]any{"recipient_email": rec.Email},
	})

	if remaining > 0 {
		return &Result{DocumentID: doc.ID, Status: "in_progress", Completed: false}, nil
	}

	// Every acceptor has accepted: complete WITHOUT the ed25519 finalize. The
	// final artifact is the original upload; a failure here just leaves the doc
	// in_progress (a later accept re-attempts completion).
	rows, cerr := e.Queries.CompleteAcknowledgedDocument(ctx, generated.CompleteAcknowledgedDocumentParams{ID: doc.ID, OrgID: doc.OrgID})
	if cerr != nil || rows == 0 {
		return &Result{DocumentID: doc.ID, Status: "in_progress", Completed: false}, nil
	}
	_ = e.Queries.InvalidateRecipientTokens(ctx, doc.ID)
	finalKey := ""
	if lockedDoc.PdfStorageKey.Valid {
		finalKey = lockedDoc.PdfStorageKey.String
	}
	// Bind the acknowledged document's content digest into the append-only audit
	// chain, mirroring afterFinalize on the signed path. Without it the chain
	// attests only {"mode":"acknowledgement"} and an object-store swap of the
	// final artifact goes undetected; the digest lets the evidence bundle's
	// recomputed FinalPDFSHA256 be checked against the immutable chain.
	completePayload := map[string]any{"mode": "acknowledgement", "final_pdf_key": finalKey}
	if len(lockedDoc.PdfSha256) == 32 {
		completePayload["final_pdf_sha256"] = fmt.Sprintf("%x", lockedDoc.PdfSha256)
	}
	_, _ = e.Audit.Log(ctx, audit.Entry{
		OrgID: doc.OrgID, DocumentID: &doc.ID,
		Kind:    audit.KindDocumentCompleted,
		Payload: completePayload,
	})
	return &Result{DocumentID: doc.ID, Status: "completed", Completed: true, FinalPDFKey: finalKey}, nil
}

// afterFinalize emits the completion audit event and side effects once a
// document's final PDF + cert are persisted. Shared by the inline last-signer
// path and the finalize-retry worker so both emit identical events/emails.
func (e *Engine) afterFinalize(ctx context.Context, doc *generated.Document, finalKey, certKey string) {
	payload := map[string]any{"final_pdf_key": finalKey, "audit_cert_key": certKey}
	// Bind the final PDF digest into the completion event so the ed25519-anchored
	// audit hash chain covers the exact signed document bytes. Without this an
	// actor with object-store write could swap final.pdf and no signed structure
	// would detect it (envelope children already bind via the manifest).
	if fresh, err := e.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: doc.OrgID}); err == nil && len(fresh.FinalPdfSha) > 0 {
		payload["final_pdf_sha256"] = fmt.Sprintf("%x", fresh.FinalPdfSha)
	}
	_, _ = e.Audit.Log(ctx, audit.Entry{
		OrgID: doc.OrgID, DocumentID: &doc.ID,
		Kind:    audit.KindDocumentCompleted,
		Payload: payload,
	})
	e.notifyCompleted(ctx, doc, finalKey)
	// Phase 8.6.1: envelope completion propagates to every child.
	e.propagateEnvelopeCompletion(ctx, doc, finalKey, certKey)
}

// FinalizeStranded re-runs finalize for a document whose signers all signed
// but whose finalize failed (Gotenberg/MinIO outage). Invoked by the
// finalize-retry worker loop. Idempotent: a no-op if the document is already
// finalized or another finalize is in flight.
func (e *Engine) FinalizeStranded(ctx context.Context, orgID, docID uuid.UUID) error {
	finalKey, certKey, did, err := e.finalize(ctx, orgID, docID)
	if errors.Is(err, ErrFinalizeInProgress) {
		return nil
	}
	if err != nil {
		return err
	}
	if !did {
		return nil
	}
	doc, err := e.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: docID, OrgID: orgID})
	if err != nil {
		return err
	}
	e.afterFinalize(ctx, doc, finalKey, certKey)
	return nil
}

// propagateEnvelopeCompletion fans the envelope's terminal state out
// to every child document so list views + dashboards + the
// compliance-flag walker all see consistent state. Children inherit
// the envelope's final_pdf_key + final_pdf_sha so re-renders against
// a child id work without re-finalizing.
func (e *Engine) propagateEnvelopeCompletion(ctx context.Context, envelope *generated.Document, finalKey, certKey string) {
	if !envelope.IsEnvelope || e.EnvelopeChildren == nil {
		return
	}
	children, err := e.EnvelopeChildren(ctx, envelope)
	if err != nil {
		return
	}
	for _, child := range children {
		if child == nil {
			continue
		}
		_, _ = e.Queries.SetDocumentStatus(ctx, generated.SetDocumentStatusParams{
			ID: child.ID, OrgID: envelope.OrgID, Status: "completed",
		})
		_, _ = e.Audit.Log(ctx, audit.Entry{
			OrgID: envelope.OrgID, DocumentID: &child.ID,
			Kind: audit.KindDocumentCompleted,
			Payload: map[string]any{
				"via":            "envelope",
				"envelope_id":    envelope.ID.String(),
				"final_pdf_key":  finalKey,
				"audit_cert_key": certKey,
				"propagated":     true,
			},
		})
	}
}

// notifyCompleted ships completion emails to all signers + the sender.
// Best-effort fire-and-forget; failures log but don't affect the response.
func (e *Engine) notifyCompleted(ctx context.Context, doc *generated.Document, finalKey string) {
	if e.Mailer == nil {
		return
	}
	recs, err := e.Queries.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil {
		return
	}
	sender, err := e.Queries.GetUser(ctx, doc.SenderID)
	if err != nil {
		return
	}
	downloadURL := e.BaseURL + "/api/v1/documents/" + doc.ID.String() + "/final-pdf"
	_, _ = finalKey, downloadURL // finalKey is the storage key; the URL above hits the sender-auth download endpoint

	// Per-signer copy.
	for _, rec := range recs {
		if rec.Role != "signer" || rec.Status != "signed" {
			continue
		}
		ctxCopy := dispatch.TemplateContext{
			DocumentName:  doc.Name,
			SenderName:    sender.Name,
			SenderEmail:   sender.Email,
			RecipientName: rec.Name,
			OrgName:       e.OrgName,
			Locale:        rec.Locale,
			DownloadURL:   downloadURL,
		}
		go sendOne(e.Mailer, dispatch.KindCompletedSigner, rec.Email, ctxCopy)
	}
	// Sender notification.
	go sendOne(e.Mailer, dispatch.KindCompletedSender, sender.Email, dispatch.TemplateContext{
		DocumentName:  doc.Name,
		SenderName:    sender.Name,
		SenderEmail:   sender.Email,
		RecipientName: sender.Name,
		OrgName:       e.OrgName,
		DownloadURL:   downloadURL,
	})
}

// notifyDeclined emails the sender that a recipient declined.
func (e *Engine) notifyDeclined(ctx context.Context, doc *generated.Document, rec *generated.GetRecipientByTokenHashRow, reason string) {
	if e.Mailer == nil {
		return
	}
	sender, err := e.Queries.GetUser(ctx, doc.SenderID)
	if err != nil {
		return
	}
	go sendOne(e.Mailer, dispatch.KindDeclined, sender.Email, dispatch.TemplateContext{
		DocumentName:  doc.Name,
		SenderName:    sender.Name,
		SenderEmail:   sender.Email,
		RecipientName: rec.Name,
		OrgName:       e.OrgName,
		DeclineReason: reason,
	})
}

// sendOne renders + ships one email. Logs at debug-or-warn; never panics.
func sendOne(mailer dispatch.Mailer, kind, to string, tctx dispatch.TemplateContext) {
	subj, html, text, err := dispatch.Render(kind, tctx)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = mailer.Send(ctx, dispatch.Message{
		To: to, Subject: subj, HTML: html, Text: text,
		ReplyTo: tctx.SenderEmail, FromName: tctx.OrgName,
	})
}

// Decline marks a recipient as declined; the document moves to declined too.
//
// Gated against terminal documents: a recipient with a still-live magic link
// can no longer flip a completed/voided/declined/expired contract to declined,
// and an already-signed recipient cannot self-downgrade. Runs in a tx holding
// the document row lock so it can't race finalize, and invalidates every magic
// link for the document on the terminal transition.
func (e *Engine) Decline(ctx context.Context, rc *RecipientContext, reason, ip, ua string) error {
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
	if lockedDoc.Status != "sent" && lockedDoc.Status != "in_progress" {
		return ErrDocumentNotSignable
	}
	freshRec, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: rec.ID, OrgID: doc.OrgID})
	if err != nil {
		return err
	}
	if freshRec.Status == "declined" {
		return nil // idempotent
	}
	if freshRec.Status == "signed" {
		return ErrAlreadySigned
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
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit decline: %w", err)
	}

	_, _ = e.Audit.Log(ctx, audit.Entry{
		OrgID: doc.OrgID, DocumentID: &rec.DocumentID, RecipientID: &rec.ID,
		Kind:      audit.KindDocumentDeclined,
		IP:        ip,
		UserAgent: ua,
		Payload:   map[string]any{"reason": reason},
	})
	e.notifyDeclined(ctx, rc.Document, rec, reason)
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
}

func (e *Engine) RequestChanges(ctx context.Context, rc *RecipientContext, in ChangeRequestInput) error {
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
	// Allow marking several spans during the same pause.
	if lockedDoc.Status != "sent" && lockedDoc.Status != "in_progress" && lockedDoc.Status != "changes_requested" {
		return ErrDocumentNotSignable
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
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit change request: %w", err)
	}

	_, _ = e.Audit.Log(ctx, audit.Entry{
		OrgID: doc.OrgID, DocumentID: &rec.DocumentID, RecipientID: &rec.ID,
		Kind:      audit.KindChangesRequested,
		IP:        in.IP,
		UserAgent: in.UserAgent,
		Payload:   map[string]any{"message": in.Message, "block_id": in.BlockID, "quote": in.Quote},
	})
	e.notifyChangesRequested(ctx, rc.Document, rec, in, cr.ID)
	return nil
}

// notifyChangesRequested emails the sender a snippet of the marked text plus the
// requested change and a link to open the document.
func (e *Engine) notifyChangesRequested(ctx context.Context, doc *generated.Document, rec *generated.GetRecipientByTokenHashRow, in ChangeRequestInput, crID uuid.UUID) {
	if e.Mailer == nil {
		return
	}
	sender, err := e.Queries.GetUser(ctx, doc.SenderID)
	if err != nil {
		return
	}
	approveURL, denyURL := "", ""
	if e.ActionSecret != "" {
		base := actiontoken.Claims{Kind: "cr", OrgID: doc.OrgID.String(), DocID: doc.ID.String(), TargetID: crID.String()}
		approve := base
		approve.Action = "approve"
		deny := base
		deny.Action = "deny"
		approveURL = e.BaseURL + "/a/cr?t=" + actiontoken.Mint(e.ActionSecret, approve, time.Now(), 14*24*time.Hour)
		denyURL = e.BaseURL + "/a/cr?t=" + actiontoken.Mint(e.ActionSecret, deny, time.Now(), 14*24*time.Hour)
	}
	go sendOne(e.Mailer, dispatch.KindChangesRequested, sender.Email, dispatch.TemplateContext{
		DocumentName:   doc.Name,
		SenderName:     sender.Name,
		SenderEmail:    sender.Email,
		RecipientName:  rec.Name,
		OrgName:        e.OrgName,
		DeclineReason:  in.Message,
		ChangeQuote:    in.Quote,
		ChangeContext:  in.Context,
		ChangeProposed: in.Proposed,
		OpenURL:        e.BaseURL + "/documents/" + doc.ID.String(),
		ApproveURL:     approveURL,
		DenyURL:        denyURL,
	})
}

// ResolveChange approves or denies one inline change request. On approve, if the
// org's change_approval_mode is auto_apply and the request carries a marked span
// plus a proposed replacement, the marked text is swapped in the block in place;
// otherwise approval is recorded for the sender to apply during Revise.
func (e *Engine) ResolveChange(ctx context.Context, orgID, docID, crID uuid.UUID, approve bool) (*generated.ChangeRequest, error) {
	cr, err := e.Queries.GetChangeRequest(ctx, generated.GetChangeRequestParams{ID: crID, OrgID: orgID})
	if err != nil {
		return nil, err
	}
	if cr.DocumentID != docID {
		return nil, errors.New("change request does not belong to this document")
	}
	resolution := "denied"
	if approve {
		resolution = "approved"
		if org, oerr := e.Queries.GetOrg(ctx, orgID); oerr == nil && org.ChangeApprovalMode == "auto_apply" {
			e.applyChangeToBlocks(ctx, orgID, docID, cr.BlockID, cr.Quote, cr.Proposed)
		}
	}
	resolved, err := e.Queries.ResolveChangeRequest(ctx, generated.ResolveChangeRequestParams{
		ID: crID, DocumentID: docID, Resolution: pgtype.Text{String: resolution, Valid: true},
	})
	if err != nil {
		return nil, err
	}
	_, _ = e.Audit.Log(ctx, audit.Entry{
		OrgID: orgID, DocumentID: &docID,
		Kind:    audit.KindChangesRequested,
		Payload: map[string]any{"change_request": crID.String(), "resolution": resolution},
	})
	return resolved, nil
}

// applyChangeToBlocks swaps the first occurrence of quote with proposed in the
// block identified by blockID. Best effort: if the block or quote is gone (the
// text already changed), it is a no-op and approval is still recorded.
func (e *Engine) applyChangeToBlocks(ctx context.Context, orgID, docID uuid.UUID, blockID, quote, proposed string) {
	if blockID == "" || quote == "" || proposed == "" {
		return
	}
	// Serialize the read-modify-write of blocks_json under a row lock so two
	// concurrent auto-apply approvals on the same document (e.g. two one-click
	// email approvals arriving together) can't each read the same tree and
	// clobber the other's edit. The second waits, then reads the tree the first
	// already updated.
	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)
	doc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: docID, OrgID: orgID})
	if err != nil {
		return
	}
	tree, err := blocks.ParseTree(doc.BlocksJson)
	if err != nil {
		return
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
		return
	}
	raw, err := json.Marshal(tree)
	if err != nil {
		return
	}
	if _, err := q.ApplyBlocksForChange(ctx, generated.ApplyBlocksForChangeParams{ID: docID, OrgID: orgID, BlocksJson: raw}); err != nil {
		return
	}
	_ = tx.Commit(ctx)
}

// SignerComment posts a comment from a recipient on the shared document thread
// and emails the sender.
func (e *Engine) SignerComment(ctx context.Context, rc *RecipientContext, body string) (*generated.DocumentComment, error) {
	if strings.TrimSpace(body) == "" {
		return nil, errors.New("comment is empty")
	}
	rec := rc.Recipient
	doc := rc.Document
	c, err := e.Queries.CreateComment(ctx, generated.CreateCommentParams{
		DocumentID:  doc.ID,
		RecipientID: pgtype.UUID{Bytes: rec.ID, Valid: true},
		AuthorName:  rec.Name,
		AuthorSide:  "signer",
		Body:        body,
	})
	if err != nil {
		return nil, err
	}
	_, _ = e.Audit.Log(ctx, audit.Entry{
		OrgID: doc.OrgID, DocumentID: &doc.ID, RecipientID: &rec.ID,
		Kind: audit.KindCommentPosted, Payload: map[string]any{"side": "signer"},
	})
	if e.Mailer != nil {
		if sender, serr := e.Queries.GetUser(ctx, doc.SenderID); serr == nil {
			go sendOne(e.Mailer, dispatch.KindNewComment, sender.Email, dispatch.TemplateContext{
				DocumentName:  doc.Name,
				SenderName:    sender.Name,
				SenderEmail:   sender.Email,
				RecipientName: rec.Name,
				OrgName:       e.OrgName,
				DeclineReason: body,
				OpenURL:       e.BaseURL + "/documents/" + doc.ID.String(),
			})
		}
	}
	return c, nil
}

// SenderComment posts a comment from the sending org on the shared thread and
// emails each signer recipient.
func (e *Engine) SenderComment(ctx context.Context, orgID, docID, userID uuid.UUID, authorName, body string) (*generated.DocumentComment, error) {
	if strings.TrimSpace(body) == "" {
		return nil, errors.New("comment is empty")
	}
	doc, err := e.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: docID, OrgID: orgID})
	if err != nil {
		return nil, err
	}
	c, err := e.Queries.CreateComment(ctx, generated.CreateCommentParams{
		DocumentID: docID,
		UserID:     pgtype.UUID{Bytes: userID, Valid: true},
		AuthorName: authorName,
		AuthorSide: "sender",
		Body:       body,
	})
	if err != nil {
		return nil, err
	}
	_, _ = e.Audit.Log(ctx, audit.Entry{
		OrgID: orgID, DocumentID: &docID,
		Kind: audit.KindCommentPosted, Payload: map[string]any{"side": "sender"},
	})
	if e.Mailer != nil {
		if recs, rerr := e.Queries.ListRecipientsByDocument(ctx, docID); rerr == nil {
			for _, r := range recs {
				if r.Role != "signer" && r.Role != "approver" {
					continue
				}
				replyURL := ""
				if e.ActionSecret != "" {
					replyURL = e.BaseURL + "/a/comment?t=" + actiontoken.Mint(e.ActionSecret, actiontoken.Claims{
						Kind: "comment", OrgID: orgID.String(), DocID: docID.String(), TargetID: r.ID.String(), Action: "reply",
					}, time.Now(), 14*24*time.Hour)
				}
				go sendOne(e.Mailer, dispatch.KindNewComment, r.Email, dispatch.TemplateContext{
					DocumentName:  doc.Name,
					OrgName:       e.OrgName,
					RecipientName: authorName,
					DeclineReason: body,
					ReplyURL:      replyURL,
				})
			}
		}
	}
	return c, nil
}

// CommentAsRecipient posts a comment authored by a specific recipient. Used by
// the one-click email reply path, where the recipient is identified by a signed
// token rather than their magic link.
func (e *Engine) CommentAsRecipient(ctx context.Context, orgID, docID, recipientID uuid.UUID, body string) (*generated.DocumentComment, error) {
	if strings.TrimSpace(body) == "" {
		return nil, errors.New("comment is empty")
	}
	rec, err := e.Queries.GetRecipient(ctx, generated.GetRecipientParams{ID: recipientID, OrgID: orgID})
	if err != nil {
		return nil, err
	}
	doc, err := e.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: docID, OrgID: orgID})
	if err != nil {
		return nil, err
	}
	// Only an active document accepts signer comments. A stale comment-reply
	// action token (14-day TTL, not cleared on terminal transitions) must not
	// mutate a completed/voided/declined/expired legal record.
	switch doc.Status {
	case "sent", "in_progress", "changes_requested":
		// active
	default:
		return nil, ErrDocumentNotCommentable
	}
	c, err := e.Queries.CreateComment(ctx, generated.CreateCommentParams{
		DocumentID:  docID,
		RecipientID: pgtype.UUID{Bytes: recipientID, Valid: true},
		AuthorName:  rec.Name,
		AuthorSide:  "signer",
		Body:        body,
	})
	if err != nil {
		return nil, err
	}
	_, _ = e.Audit.Log(ctx, audit.Entry{
		OrgID: orgID, DocumentID: &docID, RecipientID: &recipientID,
		Kind: audit.KindCommentPosted, Payload: map[string]any{"side": "signer", "via": "email"},
	})
	if e.Mailer != nil {
		if sender, serr := e.Queries.GetUser(ctx, doc.SenderID); serr == nil {
			go sendOne(e.Mailer, dispatch.KindNewComment, sender.Email, dispatch.TemplateContext{
				DocumentName:  doc.Name,
				SenderName:    sender.Name,
				SenderEmail:   sender.Email,
				RecipientName: rec.Name,
				OrgName:       e.OrgName,
				DeclineReason: body,
				OpenURL:       e.BaseURL + "/documents/" + docID.String(),
			})
		}
	}
	return c, nil
}

// Revise reopens a changes_requested document to draft so the sender can edit it
// and re-send. It resolves the open change requests, voids any signatures from
// the previous version, and resets recipients to pending so the re-send mints
// fresh links and the new draft is signed cleanly.
func (e *Engine) Revise(ctx context.Context, orgID, docID uuid.UUID) (*generated.Document, error) {
	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)

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
	if err := q.DeleteSignaturesByDocument(ctx, docID); err != nil {
		return nil, err
	}
	if err := q.ResetRecipientsForRevision(ctx, docID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit revise: %w", err)
	}

	_, _ = e.Audit.Log(ctx, audit.Entry{
		OrgID: orgID, DocumentID: &docID,
		Kind: audit.KindDocumentRevised,
	})
	return doc, nil
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

	if rc.Document.IsEnvelope && e.EnvelopeChildren != nil {
		body, err := e.renderEnvelopeBody(ctx, rc.Document, rc.Recipient.Locale)
		if err != nil {
			return "", err
		}
		return buildHTMLDocument(brandCSS, body, ""), nil
	}

	tree, err := blocks.ParseTree(rc.Document.BlocksJson)
	if err != nil {
		return "", err
	}
	vars := varsFromJSON(rc.Document.VariablesJson)
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
	children, err := e.EnvelopeChildren(ctx, envelope)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	fmt.Fprintf(&sb,
		`<section class="hash-envelope-banner"><h1>%s</h1><p class="hash-envelope-note">This envelope bundles %d documents that are signed together as a single legal instrument.</p></section>`,
		htmlEscape(envelope.Name), len(children))

	for i, child := range children {
		if child == nil {
			continue
		}
		tree, err := blocks.ParseTree(child.BlocksJson)
		if err != nil {
			continue
		}
		vars := varsFromJSON(child.VariablesJson)
		childBody, err := e.renderSignedHTML(ctx, tree, child.ID, vars, locale)
		if err != nil {
			continue
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
func (e *Engine) MarkViewed(ctx context.Context, rc *RecipientContext, ip, ua string) error {
	rec := rc.Recipient
	if rec.Status != "pending" && rec.Status != "sent" {
		return nil
	}
	if err := e.Queries.SetRecipientStatus(ctx, generated.SetRecipientStatusParams{
		ID: rec.ID, DocumentID: rec.DocumentID,
		Status:         "viewed",
		DeclinedReason: pgtype.Text{},
	}); err != nil {
		return err
	}
	_, _ = e.Audit.Log(ctx, audit.Entry{
		OrgID: rc.Document.OrgID, DocumentID: &rec.DocumentID, RecipientID: &rec.ID,
		Kind:      audit.KindDocumentViewed,
		IP:        ip,
		UserAgent: ua,
	})
	return nil
}

// preparedSignature holds the rendered span + its object-storage key,
// computed outside the signing transaction so no external I/O runs inside the
// document row lock.
type preparedSignature struct {
	fieldBlockID string
	imgKey       string
	sum          [32]byte
}

// prepareSignature renders the signature span, stores it to object storage,
// and resolves the recipient's signature_field block. Runs BEFORE the tx.
func (e *Engine) prepareSignature(ctx context.Context, doc *generated.Document, rec *generated.GetRecipientByTokenHashRow, in SignInput) (*preparedSignature, error) {
	// PDF-source documents have no block tree: the signature stamps onto the
	// uploaded PDF at the recipient's signature field coordinates during
	// finalize. We still render + store the span so the audit cert and the
	// signature row's ImageSha256 are populated identically to the blocks path.
	if doc.SourceKind != "blocks" {
		span := render.RenderSignatureSpan(in.TypedName, in.Font)
		sum := sha256.Sum256([]byte(span))
		imgKey := path.Join("org", doc.OrgID.String(), "signatures", uuid.NewString()+".html")
		if _, err := e.Storage.Put(ctx, imgKey, "text/html", []byte(span)); err != nil {
			return nil, fmt.Errorf("store signature span: %w", err)
		}
		return &preparedSignature{fieldBlockID: "", imgKey: imgKey, sum: sum}, nil
	}

	tree, err := blocks.ParseTree(doc.BlocksJson)
	if err != nil {
		return nil, fmt.Errorf("parse block tree: %w", err)
	}
	fieldBlock := findSignatureFieldFor(tree, rec.Role)
	if fieldBlock == nil {
		return nil, errors.New("no signature field bound to this recipient role")
	}
	span := render.RenderSignatureSpan(in.TypedName, in.Font)
	sum := sha256.Sum256([]byte(span))
	imgKey := path.Join("org", doc.OrgID.String(), "signatures", uuid.NewString()+".html")
	if _, err := e.Storage.Put(ctx, imgKey, "text/html", []byte(span)); err != nil {
		return nil, fmt.Errorf("store signature span: %w", err)
	}
	return &preparedSignature{fieldBlockID: fieldBlock.ID, imgKey: imgKey, sum: sum}, nil
}

// insertSignatureRow writes the signature + its field row through the supplied
// tx-scoped queries. A unique-index conflict (concurrent double-POST) returns
// ErrAlreadySigned rather than inserting a duplicate.
func (e *Engine) insertSignatureRow(ctx context.Context, q *generated.Queries, doc *generated.Document, recID uuid.UUID, role string, prep *preparedSignature, in SignInput) (*generated.Signature, error) {
	_ = role
	fieldRow, err := e.findOrInsertFieldTx(ctx, q, doc.ID, recID, prep.fieldBlockID)
	if err != nil {
		return nil, err
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
func (e *Engine) finalize(ctx context.Context, orgID, docID uuid.UUID) (finalKey, certKey string, didFinalize bool, err error) {
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
	cert, certPayload, certSignature, err := e.renderAuditCertificate(ctx, doc)
	if err != nil {
		return "", "", false, err
	}

	brandCSS := ""
	if e.BrandingCSS != nil {
		brandCSS = e.BrandingCSS(ctx, doc)
	}

	// Render the standalone audit-certificate PDF once. It is stored as
	// audit.pdf and, for pdf-source documents, appended to the stamped final.
	certHTML := buildHTMLDocument(brandCSS, "", cert)
	certBytes, err := e.PDF.HTMLToPDF(ctx, certHTML, render.PDFOptions{})
	if err != nil {
		return "", "", false, fmt.Errorf("gotenberg render cert: %w", err)
	}

	// Final PDF differs by source. Blocks: render the signed HTML + the cert
	// into one PDF. PDF-source: stamp field values + signatures onto the
	// uploaded PDF, then append the cert page.
	var pdfBytes []byte
	if doc.SourceKind == "blocks" {
		tree, terr := blocks.ParseTree(doc.BlocksJson)
		if terr != nil {
			return "", "", false, terr
		}
		vars := varsFromJSON(doc.VariablesJson)
		signedHTML, rerr := e.renderSignedHTML(ctx, tree, doc.ID, vars, "en")
		if rerr != nil {
			return "", "", false, rerr
		}
		full := buildHTMLDocument(brandCSS, signedHTML, cert)
		pdfBytes, err = e.PDF.HTMLToPDF(ctx, full, render.PDFOptions{WaitDelay: "1500ms"})
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
		merged, merr := mergePDFs(stamped, certBytes)
		if merr != nil {
			return "", "", false, merr
		}
		pdfBytes = merged
	}

	finalKey = path.Join("org", doc.OrgID.String(), "documents", doc.ID.String(), "final.pdf")
	finalSum, err := e.Storage.Put(ctx, finalKey, "application/pdf", pdfBytes)
	if err != nil {
		return "", "", false, fmt.Errorf("store final pdf: %w", err)
	}

	certKey = path.Join("org", doc.OrgID.String(), "documents", doc.ID.String(), "audit.pdf")
	if _, err := e.Storage.Put(ctx, certKey, "application/pdf", certBytes); err != nil {
		return "", "", false, fmt.Errorf("store cert pdf: %w", err)
	}

	// Phase 10.2.1: persist the exact signed payload + detached signature
	// next to the cert PDF so the evidence bundle can embed them as
	// attachments. Without these, an offline examiner can't verify the
	// ed25519 signature because the cert PDF is a Gotenberg-rendered
	// approximation of the HTML that was actually signed (text reflow,
	// font substitution, page break edges all perturb the byte stream).
	if certPayload != "" {
		payloadKey := path.Join("org", doc.OrgID.String(), "documents", doc.ID.String(), "audit.payload.txt")
		if _, err := e.Storage.Put(ctx, payloadKey, "text/html; charset=utf-8", []byte(certPayload)); err != nil {
			return "", "", false, fmt.Errorf("store cert payload: %w", err)
		}
	}
	if certSignature != "" {
		signatureKey := path.Join("org", doc.OrgID.String(), "documents", doc.ID.String(), "audit.signature.txt")
		if _, err := e.Storage.Put(ctx, signatureKey, "text/plain; charset=utf-8", []byte(certSignature)); err != nil {
			return "", "", false, fmt.Errorf("store cert signature: %w", err)
		}
	}

	rows, err := e.Queries.SetDocumentFinal(ctx, generated.SetDocumentFinalParams{
		ID:           doc.ID,
		OrgID:        doc.OrgID,
		FinalPdfKey:  pgtype.Text{String: finalKey, Valid: true},
		FinalPdfSha:  finalSum[:],
		AuditCertKey: pgtype.Text{String: certKey, Valid: true},
	})
	if err != nil {
		return "", "", false, err
	}
	if rows == 0 {
		// The guarded write matched nothing: the document is no longer
		// in_progress (a concurrent Revise moved it to draft, or Void moved it
		// to voided) while we rendered. Do NOT complete it - the rendered PDF +
		// cert embed signatures that no longer hold. Abort; the stored render is
		// an orphan overwritten on the next real finalize.
		return "", "", false, ErrDocumentRevisedDuringFinalize
	}
	// Terminal state reached: invalidate every magic link for the document so
	// a still-live link can't drive any further mutation.
	_ = e.Queries.InvalidateRecipientTokens(ctx, doc.ID)
	return finalKey, certKey, true, nil
}

// advisoryLockKey derives a stable int64 from a document UUID for use as a
// Postgres advisory-lock key.
func advisoryLockKey(id uuid.UUID) int64 {
	return int64(binary.BigEndian.Uint64(id[:8]))
}

// findOrInsertFieldTx returns the document_fields row for a signature_field
// block, inserting a placeholder if none exists for this recipient + sig type.
// Runs through the supplied tx-scoped queries.
func (e *Engine) findOrInsertFieldTx(ctx context.Context, q *generated.Queries, docID, recID uuid.UUID, blockID string) (*generated.DocumentField, error) {
	_ = blockID
	rows, err := q.ListFieldsByDocument(ctx, docID)
	if err != nil {
		return nil, err
	}
	for _, f := range rows {
		if f.RecipientID.Valid && uuid.UUID(f.RecipientID.Bytes) == recID && f.Type == "signature" {
			return f, nil
		}
	}
	zero := pgtype.Numeric{Int: big.NewInt(0), Exp: 0, Valid: true}
	row, err := q.CreateField(ctx, generated.CreateFieldParams{
		DocumentID:  docID,
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

// signerRolesForDoc returns the recipient roles that must sign before the
// document completes: always 'signer', plus any role referenced by a signature
// field in a block document (e.g. a provider 'approver' counter-signature).
// PDF documents have no signature-field blocks and fall back to 'signer'.
func signerRolesForDoc(doc *generated.Document) []string {
	roles := map[string]struct{}{"signer": {}}
	if doc.SourceKind == "blocks" {
		if tree, err := blocks.ParseTree(doc.BlocksJson); err == nil {
			for _, r := range blocks.RequiredSignerRoles(tree) {
				roles[r] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(roles))
	for r := range roles {
		out = append(out, r)
	}
	return out
}

func findSignatureFieldFor(t *blocks.Tree, role string) *blocks.Block {
	for i := range t.Blocks {
		b := &t.Blocks[i]
		if b.Type != blocks.TypeSignatureField {
			continue
		}
		want := b.AttrString("recipient_role", "")
		if want == role || want == "" {
			return b
		}
	}
	return nil
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
	bySigner := map[string]*generated.Signature{}
	for _, s := range sigs {
		bySigner[s.RecipientID.String()] = s
	}
	var recs []*generated.Recipient
	if e.Queries != nil {
		var err error
		recs, err = e.Queries.ListRecipientsByDocument(ctx, docID)
		if err != nil {
			return "", err
		}
	}

	for i := range tree.Blocks {
		b := &tree.Blocks[i]
		if b.Type != blocks.TypeSignatureField {
			continue
		}
		role := b.AttrString("recipient_role", "")
		var signedSpan string
		for _, rec := range recs {
			if rec.Role != role {
				continue
			}
			if s, ok := bySigner[rec.ID.String()]; ok {
				signedSpan = render.RenderSignatureSpan(s.TypedName, s.Font)
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
	return blocks.RenderHTML(tree, vars), nil
}

// renderAuditCertificate emits the HTML for the audit-certificate page.
// Returns the rendered HTML, the exact bytes that were signed (the cert
// payload before the signature display block is appended), and the
// detached base64 signature. The Phase 10.2.1 evidence bundle persists
// payload + signature alongside the cert PDF so a forensic examiner can
// verify the ed25519 signature offline without re-rendering anything.
func (e *Engine) renderAuditCertificate(ctx context.Context, doc *generated.Document) (html, signedPayload, signature string, err error) {
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
	completedAt := formatNullableTS(doc.CompletedAt)
	if !doc.CompletedAt.Valid {
		completedAt = time.Now().UTC().Format(time.RFC3339)
	}
	fmt.Fprintf(&sb, `<p><strong>Completed at:</strong> %s</p>`, completedAt)

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

	// Phase 8.6: append the envelope manifest section BEFORE signing so
	// the ed25519 signature covers the manifest hashes too. Empty for
	// non-envelope docs; for envelopes it lists every child PDF's
	// SHA-256 + position + status, transitively binding the bundle.
	if e.EnvelopeManifestHTML != nil {
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
	if e.Signer != nil {
		signedPayload = sb.String()
		signature = e.Signer.SignPayload([]byte(signedPayload))
		fmt.Fprintf(&sb, `<div style="margin-top:24px;padding:12px;border:1px solid #ddd;background:#fafafa;font-family:monospace;font-size:9px;line-height:1.5;">
<div><strong>Issuer:</strong> Hash / Bright Interaction AB</div>
<div><strong>Public key (ed25519, base64):</strong> %s</div>
<div><strong>Signature (ed25519 over SHA-256(domain ‖ cert)):</strong> %s</div>
<div style="color:#666;margin-top:6px">Verify offline: see https://esign.brightinteraction.com/verify</div>
</div>`,
			htmlEscape(e.Signer.PublicKeyBase64()),
			htmlEscape(signature))
	} else {
		sb.WriteString(`<p style="margin-top:16px;font-size:10px;color:#666">Issued by Hash / Bright Interaction. Verify the document hash by recomputing SHA-256 over the bytes of the final PDF.</p>`)
	}
	sb.WriteString(`</div>`)
	return sb.String(), signedPayload, signature, nil
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
	if len(v) <= max {
		return v
	}
	return v[:max] + "… [truncated, full value in document_fields]"
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

func varsFromJSON(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return out
	}
	for k, v := range m {
		switch x := v.(type) {
		case string:
			out[k] = x
		case float64:
			out[k] = fmt.Sprintf("%v", x)
		case bool:
			if x {
				out[k] = "true"
			} else {
				out[k] = "false"
			}
		}
	}
	return out
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
