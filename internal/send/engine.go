// Package send owns the document lifecycle transitions that move a draft out
// into the world and follow it up: send, void, remind. It exists because that
// logic was previously duplicated between the REST handlers and the MCP
// workflow tools, and the copies drifted: the MCP + worker paths minted magic
// links with a NULL expiry (the TTL fix was applied per-surface), and MCP send
// skipped the variable freeze, the eIDAS guard, and the billing quota.
//
// Every surface (REST, MCP, worker) now routes through this one engine, so the
// invariants live in exactly one place and cannot be forgotten by a new
// caller. The magic-token TTL specifically funnels through rotateToken, the
// single chokepoint that always sets the expiry.
package send

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/billing"
	"github.com/brightinteraction/hash/internal/blocks"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/dispatch"
	"github.com/brightinteraction/hash/internal/eidas"
	"github.com/brightinteraction/hash/internal/envelopes"
	"github.com/brightinteraction/hash/internal/magictoken"
	"github.com/brightinteraction/hash/internal/resolver"
)

// Sentinel errors so callers can map lifecycle conflicts to the right HTTP
// status (REST) or tool error (MCP). Provider errors (eidas.GuardError,
// billing.ErrQuotaExceeded) are passed through unwrapped for the same reason.
var (
	ErrDocumentNotFound     = errors.New("document not found")
	ErrNotDraft             = errors.New("document not in draft state")
	ErrNoSigners            = errors.New("document needs at least one signer recipient before send")
	ErrNoRecipients         = errors.New("document needs at least one recipient before send")
	ErrMissingSignerForRole = errors.New("a signature field has no recipient assigned to its role")
	ErrAlreadyFinalised     = errors.New("document already finalised")
	ErrNotRemindable        = errors.New("document not in a remindable state")
)

// Actor identifies who is driving a transition. The explicit org + actor (no
// http.Request) means the worker and automatic paths use the same engine.
type Actor struct {
	UserID *uuid.UUID
	OrgID  uuid.UUID
	Email  string
	IP     string
	Via    string // "rest" | "mcp" | "worker"
	Tool   string // optional MCP tool name
}

// Engine ties together the dependencies the lifecycle transitions need. The
// Resolver/EIDAS/Billing/Envelopes engines are nil-safe so unit tests + dev
// can run without them.
type Engine struct {
	Pool      *pgxpool.Pool
	Queries   *generated.Queries
	Audit     *audit.Logger
	Mailer    dispatch.Mailer
	Resolver  *resolver.Resolver
	EIDAS     *eidas.Engine
	Billing   *billing.Engine
	Envelopes *envelopes.Engine
	PublicURL string
	OrgName   string
	Now       func() time.Time
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// SignLink is one recipient's signing URL, returned to the caller so it can be
// displayed or emailed.
type SignLink struct {
	RecipientID uuid.UUID `json:"recipient_id"`
	Email       string    `json:"email"`
	Name        string    `json:"name"`
	Role        string    `json:"role"`
	URL         string    `json:"url"`
}

// SendResult is what Send returns on success.
type SendResult struct {
	Status string     `json:"status"`
	Links  []SignLink `json:"links"`
}

// Send transitions a draft -> sent: enforces the billing quota, freezes
// variables, applies the eIDAS tier guard, then mints a magic link per
// recipient (always with an expiry), flips statuses, sets the reminder
// schedule, and queues invite emails. Returns billing.ErrQuotaExceeded /
// *eidas.GuardError for the caller to surface.
func (e *Engine) Send(ctx context.Context, a Actor, docID uuid.UUID) (SendResult, error) {
	doc, err := e.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: docID, OrgID: a.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return SendResult{}, ErrDocumentNotFound
	}
	if err != nil {
		return SendResult{}, err
	}
	if doc.Status != "draft" {
		return SendResult{}, ErrNotDraft
	}

	if e.Billing != nil {
		if err := e.Billing.EnforceDocumentQuota(ctx, a.OrgID); err != nil {
			_ = e.log(ctx, a, &doc.ID, nil, audit.KindBillingQuotaExceeded, map[string]any{"error": err.Error()})
			return SendResult{}, err
		}
	}

	recs, err := e.Queries.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil {
		return SendResult{}, err
	}
	signers := 0
	for _, rec := range recs {
		if rec.Role == "signer" {
			signers++
		}
	}
	if doc.RequiresSignature {
		if signers == 0 {
			return SendResult{}, ErrNoSigners
		}
	} else if len(recs) == 0 {
		// Acknowledgement mode: no signer required, but there must be at least
		// one recipient to send it to.
		return SendResult{}, ErrNoRecipients
	}

	// Every role that has a signature field needs a recipient to sign it, so a
	// two-party agreement (e.g. client 'signer' + provider 'approver') can't be
	// sent half-assigned and complete with a blank counter-signature.
	if doc.SourceKind == "blocks" {
		if tree, perr := blocks.ParseTree(doc.BlocksJson); perr == nil {
			have := map[string]bool{}
			for _, rec := range recs {
				have[rec.Role] = true
			}
			for _, role := range blocks.RequiredSignerRoles(tree) {
				if !have[role] {
					return SendResult{}, fmt.Errorf("%w: %s", ErrMissingSignerForRole, role)
				}
			}
		}
	}

	// Freeze variables so the snapshot captures resolved values.
	if e.Resolver != nil {
		frozen, _, ferr := e.Resolver.FreezeForSend(ctx, doc)
		if ferr != nil {
			return SendResult{}, fmt.Errorf("freeze variables: %w", ferr)
		}
		updated, uerr := e.Queries.UpdateDocumentBlocks(ctx, generated.UpdateDocumentBlocksParams{
			ID: doc.ID, OrgID: doc.OrgID, BlocksJson: doc.BlocksJson, VariablesJson: frozen,
		})
		if uerr != nil {
			return SendResult{}, fmt.Errorf("persist frozen vars: %w", uerr)
		}
		doc = updated
	}

	// eIDAS tier guard against the frozen variables.
	if e.EIDAS != nil {
		if _, gerr := e.EIDAS.GuardSend(ctx, doc.OrgID, eidas.Tier(doc.RoutingTier), BuildEIDASEvaluateInput(doc)); gerr != nil {
			return SendResult{}, gerr
		}
	}

	now := e.now()
	exp := magictoken.Expiry(doc.ExpiresAt, now)

	// Transactional core: lock the document, re-check draft UNDER the lock, then mint
	// tokens + flip recipient/doc/child statuses + set the reminder schedule
	// atomically. Without this, two concurrent sends (REST + MCP) both passed the
	// unlocked draft check and double-minted tokens (each rotation invalidated the
	// other's just-emailed link), and any mid-loop error left some recipients invited
	// + emailed while the document stayed draft with no reminder schedule. This is the
	// airtight pattern the Sign path already uses; Send had never adopted it.
	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return SendResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)

	lockedDoc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: doc.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return SendResult{}, ErrDocumentNotFound
	}
	if err != nil {
		return SendResult{}, fmt.Errorf("lock document: %w", err)
	}
	if lockedDoc.Status != "draft" {
		// A concurrent send won the race (or it was already sent): lose cleanly.
		return SendResult{}, ErrNotDraft
	}
	doc = lockedDoc

	type pendingInvite struct {
		recID                     uuid.UUID
		email, name, role, locale string
		signURL, beaconURL        string
	}
	out := SendResult{Status: "sent", Links: make([]SignLink, 0, len(recs))}
	invites := make([]pendingInvite, 0, len(recs))
	for _, rec := range recs {
		tok, err := e.rotateToken(ctx, q, rec.ID, doc.ID, exp)
		if err != nil {
			return SendResult{}, err
		}
		if err := q.SetRecipientStatus(ctx, generated.SetRecipientStatusParams{
			ID: rec.ID, DocumentID: doc.ID, Status: "sent",
		}); err != nil {
			return SendResult{}, fmt.Errorf("mark sent: %w", err)
		}
		signURL := e.PublicURL + "/sign/" + tok
		beaconURL := e.PublicURL + "/e/o/" + tok
		out.Links = append(out.Links, SignLink{RecipientID: rec.ID, Email: rec.Email, Name: rec.Name, Role: rec.Role, URL: signURL})
		invites = append(invites, pendingInvite{rec.ID, rec.Email, rec.Name, rec.Role, rec.Locale, signURL, beaconURL})
	}

	if _, err := q.SetDocumentStatus(ctx, generated.SetDocumentStatusParams{
		ID: doc.ID, OrgID: doc.OrgID, Status: "sent",
	}); err != nil {
		return SendResult{}, fmt.Errorf("set status: %w", err)
	}

	// Envelope children mirror the envelope's lifecycle, in the same tx.
	var childIDs []uuid.UUID
	if doc.IsEnvelope && e.Envelopes != nil {
		if children, cerr := e.Envelopes.Children(ctx, doc.ID, doc.OrgID); cerr == nil {
			for _, child := range children {
				if _, serr := q.SetDocumentStatus(ctx, generated.SetDocumentStatusParams{ID: child.ID, OrgID: doc.OrgID, Status: "sent"}); serr == nil {
					childIDs = append(childIDs, child.ID)
				}
			}
		}
	}

	if err := q.UpsertReminderSchedule(ctx, generated.UpsertReminderScheduleParams{
		DocumentID:     doc.ID,
		Column2:        []byte(`[{"days_after_send":3},{"days_after_send":7}]`),
		FiresRemaining: 2,
	}); err != nil {
		return SendResult{}, fmt.Errorf("reminder schedule: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return SendResult{}, fmt.Errorf("commit send: %w", err)
	}

	// Post-commit side effects: audit rows + invite emails fire ONLY after the send
	// durably landed, so a rolled-back tx never emails a counterparty or logs a
	// phantom "invited" event for a document that never reached sent.
	for _, inv := range invites {
		_ = e.log(ctx, a, &doc.ID, &inv.recID, audit.KindRecipientInvited, map[string]any{"email": inv.email, "role": inv.role})
		e.sendEmail(dispatch.KindInvite, inv.email, inv.name, doc.Name, a.Email, inv.signURL, inv.beaconURL, inv.locale)
	}
	for i := range childIDs {
		_ = e.log(ctx, a, &childIDs[i], nil, audit.KindDocumentSent, map[string]any{"envelope_id": doc.ID.String(), "propagated": true})
	}
	_ = e.log(ctx, a, &doc.ID, nil, audit.KindDocumentSent, map[string]any{"recipient_count": len(out.Links)})
	return out, nil
}

// Void moves a sent/in-progress document to voided, cancels reminders, and
// invalidates every magic link so a still-live link can do nothing further.
func (e *Engine) Void(ctx context.Context, a Actor, docID uuid.UUID, reason string) error {
	doc, err := e.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: docID, OrgID: a.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDocumentNotFound
	}
	if err != nil {
		return err
	}
	if doc.Status == "completed" || doc.Status == "voided" {
		return ErrAlreadyFinalised
	}
	// Guarded, atomic status transition (row-locked WHERE status NOT IN
	// completed/voided). Without this the read above and an unguarded write
	// raced a concurrent finalize: finalize (holding only the advisory lock,
	// not a row lock) flips the doc to 'completed', then Void clobbers it back
	// to 'voided', discarding a finalized legal record. No matched row means it
	// was completed/voided concurrently.
	if _, err := e.Queries.VoidDocumentIfActive(ctx, generated.VoidDocumentIfActiveParams{ID: doc.ID, OrgID: doc.OrgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAlreadyFinalised
		}
		return err
	}
	_ = e.Queries.CancelReminder(ctx, doc.ID)
	_ = e.Queries.InvalidateRecipientTokens(ctx, doc.ID)
	_ = e.log(ctx, a, &doc.ID, nil, audit.KindDocumentVoided, map[string]any{"reason": reason})
	return nil
}

// Remind re-mints magic links (always with an expiry) and re-sends reminder
// emails to recipients still pending on a sent/in-progress document. The
// automatic flag distinguishes the worker's scheduled fire from a manual
// remind; the worker continues to own AdvanceReminder, so a manual remind also
// pushes the next scheduled fire out.
func (e *Engine) Remind(ctx context.Context, a Actor, docID uuid.UUID, automatic bool) (int, error) {
	doc, err := e.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: docID, OrgID: a.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrDocumentNotFound
	}
	if err != nil {
		return 0, err
	}
	if doc.Status != "sent" && doc.Status != "in_progress" {
		return 0, ErrNotRemindable
	}
	recs, err := e.Queries.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil {
		return 0, err
	}
	now := e.now()
	exp := magictoken.Expiry(doc.ExpiresAt, now)

	// Mint the reminder tokens (and the manual-remind reset) in one tx under a row
	// lock + remindable re-check, so a concurrent remind/void cannot interleave token
	// rotations. Reminder emails fire only after commit.
	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)
	lockedDoc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return 0, fmt.Errorf("lock document: %w", err)
	}
	if lockedDoc.Status != "sent" && lockedDoc.Status != "in_progress" {
		return 0, ErrNotRemindable
	}
	type pendingReminder struct {
		recID               uuid.UUID
		email, name, locale string
		signURL, beaconURL  string
	}
	reminders := make([]pendingReminder, 0, len(recs))
	for _, rec := range recs {
		if rec.Status != "pending" && rec.Status != "sent" && rec.Status != "viewed" {
			continue
		}
		tok, err := e.rotateToken(ctx, q, rec.ID, doc.ID, exp)
		if err != nil {
			return 0, err
		}
		reminders = append(reminders, pendingReminder{rec.ID, rec.Email, rec.Name, rec.Locale,
			e.PublicURL + "/sign/" + tok, e.PublicURL + "/e/o/" + tok})
	}
	if !automatic {
		_ = q.ResetReminderAfterManualRemind(ctx, doc.ID)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit remind: %w", err)
	}

	for _, rm := range reminders {
		e.sendEmail(dispatch.KindReminder, rm.email, rm.name, doc.Name, a.Email, rm.signURL, rm.beaconURL, rm.locale)
		payload := map[string]any{}
		if automatic {
			payload["automatic"] = true
		} else {
			payload["manual"] = true
		}
		_ = e.log(ctx, a, &doc.ID, &rm.recID, audit.KindReminderSent, payload)
	}
	return len(reminders), nil
}

// rotateToken is THE chokepoint for the magic-token TTL invariant: it mints a
// fresh token and rotates it WITH an expiry. Every mint funnels through here so
// no caller can ever leave magic_token_expires_at NULL again.
// rotateToken takes an explicit Queries handle (the pool's or a tx's) so a caller
// running inside a transaction mints under the same atomic unit as its status flips.
func (e *Engine) rotateToken(ctx context.Context, q *generated.Queries, recipientID, documentID uuid.UUID, exp pgtype.Timestamptz) (string, error) {
	tok, hash, err := auth.MintMagicToken()
	if err != nil {
		return "", fmt.Errorf("token mint: %w", err)
	}
	if err := q.RotateRecipientMagicToken(ctx, generated.RotateRecipientMagicTokenParams{
		ID: recipientID, DocumentID: documentID, MagicTokenHash: hash, MagicTokenExpiresAt: exp,
	}); err != nil {
		return "", fmt.Errorf("rotate token: %w", err)
	}
	return tok, nil
}

func (e *Engine) sendEmail(kind, toEmail, toName, docName, senderEmail, signURL, beaconURL, locale string) {
	if e.Mailer == nil {
		return
	}
	subj, html, text, err := dispatch.Render(kind, dispatch.TemplateContext{
		DocumentName:  docName,
		SenderName:    senderEmail,
		SenderEmail:   senderEmail,
		RecipientName: toName,
		OrgName:       e.OrgName,
		Locale:        locale,
		SignURL:       signURL,
		BeaconURL:     beaconURL,
	})
	if err != nil {
		slog.Warn("send: email template render failed", "kind", kind, "err", err)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := e.Mailer.Send(ctx, dispatch.Message{
			To: toEmail, Subject: subj, HTML: html, Text: text,
			ReplyTo: senderEmail, FromName: e.OrgName,
		}); err != nil {
			slog.Warn("send: email send failed", "to", toEmail, "kind", kind, "err", err)
		}
	}()
}

func (e *Engine) log(ctx context.Context, a Actor, docID, recID *uuid.UUID, kind string, payload map[string]any) error {
	if payload == nil {
		payload = map[string]any{}
	}
	if a.Via != "" {
		payload["via"] = a.Via
	}
	if a.Tool != "" {
		payload["tool"] = a.Tool
	}
	_, err := e.Audit.Log(ctx, audit.Entry{
		OrgID: a.OrgID, ActorUserID: a.UserID, DocumentID: docID, RecipientID: recID,
		Kind: kind, IP: a.IP, Payload: payload,
	})
	return err
}

// BuildEIDASEvaluateInput pulls the fields the eIDAS engine reasons over out of
// a document row (moved from the handler so REST + MCP share one builder).
func BuildEIDASEvaluateInput(doc *generated.Document) eidas.EvaluateInput {
	in := eidas.EvaluateInput{Variables: map[string]string{}}
	if len(doc.VariablesJson) == 0 {
		return in
	}
	var raw map[string]any
	if err := json.Unmarshal(doc.VariablesJson, &raw); err != nil {
		return in
	}
	for k, v := range raw {
		if s, ok := stringifyVarForEIDAS(v); ok {
			in.Variables[k] = s
		}
	}
	for _, key := range []string{"amount", "deal_amount", "total", "value"} {
		if v, ok := in.Variables[key]; ok {
			if n, err := strconv.ParseFloat(v, 64); err == nil {
				in.Amount = n
				break
			}
		}
	}
	for _, key := range []string{"country", "jurisdiction", "country_code"} {
		if v, ok := in.Variables[key]; ok {
			in.Country = v
			break
		}
	}
	for _, key := range []string{"document_type", "doc_type", "type"} {
		if v, ok := in.Variables[key]; ok {
			in.DocumentType = v
			break
		}
	}
	return in
}

func stringifyVarForEIDAS(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10), true
		}
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	case nil:
		return "", false
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return "", false
		}
		return string(raw), true
	}
}
