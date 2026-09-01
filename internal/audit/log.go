// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package audit emits canonical event rows. Every state-changing action in
// Hash must call Log so the document timeline, audit certificate, and
// outbound webhooks all see the same source of truth.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// Event kinds are namespaced strings ,  every transition the platform reports
// to the outside world uses one of these.
const (
	KindDocumentCreated     = "document.created"
	KindDocumentUpdated     = "document.updated"
	KindDocumentSent        = "document.sent"
	KindDocumentOpened      = "document.opened" // email beacon hit
	KindDocumentViewed      = "document.viewed" // signer link click
	KindDocumentFieldFill   = "document.field_filled"
	KindDocumentSigned      = "document.signed"   // per-recipient signature captured
	KindDocumentAccepted    = "document.accepted" // acknowledgement-mode accept (no signature)
	KindDocumentCompleted   = "document.completed"
	KindDocumentDeclined    = "document.declined"
	KindChangesRequested    = "document.changes_requested"
	KindDocumentRevised     = "document.revised"
	KindCommentPosted       = "document.comment_posted"
	KindDocumentVoided      = "document.voided"
	KindDocumentExpired     = "document.expired"
	KindRecipientCreated    = "recipient.created"
	KindRecipientInvited    = "recipient.invited"
	KindRecipientUpdated    = "recipient.updated"
	KindRecipientDeleted    = "recipient.deleted"
	KindRecipientBounced    = "recipient.bounced"
	KindReminderSent        = "reminder.sent"
	KindMemberCreated       = "member.created"
	KindMemberIdentityBound = "member.identity_bound"
	KindWebhookReceived     = "webhook.received"
	KindWebhookDispatched   = "webhook.dispatched"
	KindWebhookFailed       = "webhook.failed"
	KindTemplateCreated     = "template.created"
	KindTemplateUpdated     = "template.updated"
	KindTemplateArchived    = "template.archived"

	// v1.1: first-class kinds for the new feature surfaces. Previously
	// these events piggy-backed on KindDocumentUpdated with a
	// payload.via discriminator, which made the timeline + activity
	// feed harder to filter. Each subsystem now emits its own kind.
	KindQESSessionStarted            = "qes.session_started"
	KindQESSessionCompleted          = "qes.session_completed"
	KindQESSessionFailed             = "qes.session_failed"
	KindCollabPeerJoined             = "collab.peer_joined"
	KindCollabPeerLeft               = "collab.peer_left"
	KindBillingCheckoutStarted       = "billing.checkout_started"
	KindBillingSubscriptionUpdated   = "billing.subscription_updated"
	KindBillingSubscriptionCancelled = "billing.subscription_cancelled"
	KindBillingQuotaExceeded         = "billing.quota_exceeded"
	KindBillingQuotaWarning80        = "billing.quota_warning_80"

	// GDPR Articles 15-22. The signer or sender raises a request via
	// the new /sign/{token}/dsr or /api/v1/dsr surface; an org admin
	// fulfills or denies it. The "fulfilled" path for erasure
	// anonymizes the recipients row (Art. 17(3)(e) retention override
	// keeps the signed PDF) and emits KindDataSubjectAnonymized too.
	KindDataSubjectRequested  = "data_subject.requested"
	KindDataSubjectFulfilled  = "data_subject.fulfilled"
	KindDataSubjectDenied     = "data_subject.denied"
	KindDataSubjectAnonymized = "data_subject.anonymized"
)

// EventHook fires AFTER a successful audit-row insert. The hook receives
// the freshly-allocated event id plus the original Entry so subscribers
// can fan the event out to side channels (outbound webhooks, SSE
// streams, etc) without having to be wired into every call site.
// Hook callbacks must be non-blocking; long work should be queued.
type EventHook func(ctx context.Context, eventID uuid.UUID, e Entry)

// Logger writes audit rows. Wraps a sqlc Queries plus optional post-insert
// subscribers (see Subscribe). The pool backs the per-Log transaction that
// takes the per-org advisory lock so concurrent appends can't fork the chain.
type Logger struct {
	q     *generated.Queries
	pool  *pgxpool.Pool
	hooks []EventHook
}

func New(q *generated.Queries, pool *pgxpool.Pool) *Logger {
	return &Logger{q: q, pool: pool}
}

// Subscribe registers a post-insert hook. Hooks run synchronously after
// every successful Log call (one Logger has at most a handful of
// subscribers, never per-request additions). Subscribe is NOT safe to
// call concurrently with Log; wire all hooks at startup.
func (l *Logger) Subscribe(h EventHook) {
	if h == nil {
		return
	}
	l.hooks = append(l.hooks, h)
}

// Entry is the call-side struct. Only OrgID and Kind are required.
type Entry struct {
	OrgID       uuid.UUID
	DocumentID  *uuid.UUID
	RecipientID *uuid.UUID
	ActorUserID *uuid.UUID
	Kind        string
	IP          string // empty = no IP captured
	UserAgent   string // empty = no UA captured
	Payload     map[string]any
}

// PendingEvent is an audit row appended inside a caller-owned transaction but
// not yet published to post-commit hooks. Call Publish only after that
// transaction commits successfully.
type PendingEvent struct {
	ID    uuid.UUID
	Entry Entry
}

type preparedEntry struct {
	entry     Entry
	raw       []byte
	ipAddr    *netip.Addr
	ipString  string
	createdAt time.Time
}

func prepareEntry(e Entry) (preparedEntry, error) {
	if e.OrgID == uuid.Nil {
		return preparedEntry{}, errors.New("audit: org_id required")
	}
	if e.Kind == "" {
		return preparedEntry{}, errors.New("audit: kind required")
	}
	payload := e.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return preparedEntry{}, err
	}

	var ipAddr *netip.Addr
	ipStr := ""
	if e.IP != "" {
		if addr, perr := netip.ParseAddr(e.IP); perr == nil {
			ipAddr = &addr
			ipStr = addr.String() // normalized form the verifier reconstructs
		}
	}
	// Postgres timestamptz is microsecond resolution; truncate so the value we
	// hash equals the value read back (otherwise the verifier recomputes a
	// different created_at and reports false tampering).
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	return preparedEntry{entry: e, raw: raw, ipAddr: ipAddr, ipString: ipStr, createdAt: createdAt}, nil
}

func (l *Logger) append(ctx context.Context, q *generated.Queries, p preparedEntry) (uuid.UUID, error) {
	e := p.entry

	if err := q.AcquireOrgChainLock(ctx, e.OrgID.String()); err != nil {
		return uuid.Nil, fmt.Errorf("audit: chain lock: %w", err)
	}
	head, prevErr := q.LatestEventChainHeadForOrg(ctx, e.OrgID)
	var prev []byte
	if prevErr != nil {
		if !errors.Is(prevErr, pgx.ErrNoRows) {
			// Fail closed: a transient head-read error must NOT silently write
			// a genesis row in the middle of a populated chain.
			slog.Error("audit: head-read failed; refusing to write to avoid genesis-mid-chain",
				"org_id", e.OrgID, "kind", e.Kind, "err", prevErr)
			return uuid.Nil, fmt.Errorf("audit: read chain head: %w", prevErr)
		}
		prev = nil // genuine empty chain (first row in this org)
	} else {
		prev = head.RowHash
		if head.CreatedAt.Valid {
			p.createdAt = nextAuditTimestamp(p.createdAt, head.CreatedAt.Time)
		}
	}

	hin := HashInput{
		Prev:      prev,
		OrgID:     e.OrgID,
		Kind:      e.Kind,
		IP:        p.ipString,
		UA:        e.UserAgent,
		CreatedAt: p.createdAt,
		Payload:   p.raw,
	}
	if e.DocumentID != nil {
		hin.DocID = *e.DocumentID
	}
	if e.RecipientID != nil {
		hin.RecID = *e.RecipientID
	}
	if e.ActorUserID != nil {
		hin.ActorID = *e.ActorUserID
	}
	rowHash := ChainHashRecord(hin)

	row, err := q.InsertEvent(ctx, generated.InsertEventParams{
		OrgID:         e.OrgID,
		DocumentID:    uuidToPg(e.DocumentID),
		RecipientID:   uuidToPg(e.RecipientID),
		ActorUserID:   uuidToPg(e.ActorUserID),
		Kind:          e.Kind,
		Ip:            p.ipAddr,
		Ua:            textOrNull(e.UserAgent),
		PayloadJson:   p.raw,
		PayloadHashed: p.raw,
		PrevHash:      prev,
		RowHash:       rowHash,
		CreatedAt:     pgtype.Timestamptz{Time: p.createdAt, Valid: true},
	})
	if err != nil {
		slog.Error("audit log insert failed", "kind", e.Kind, "err", err)
		return uuid.Nil, err
	}
	return row.ID, nil
}

// nextAuditTimestamp preserves the chain's ORDER BY created_at,id invariant
// when several LogTx calls append inside one transaction. Postgres stores
// microseconds; strictly increasing timestamps ensure the next head read always
// selects the row that was just appended, independent of random UUID ordering.
func nextAuditTimestamp(candidate, previous time.Time) time.Time {
	candidate = candidate.UTC().Truncate(time.Microsecond)
	previous = previous.UTC().Truncate(time.Microsecond)
	if !candidate.After(previous) {
		return previous.Add(time.Microsecond)
	}
	return candidate
}

// Log writes and commits an independent audit transaction. State-machine
// callers that already own a transaction should use LogTx so the legal event
// and mutation commit atomically.
func (l *Logger) Log(ctx context.Context, e Entry) (uuid.UUID, error) {
	p, err := prepareEntry(e)
	if err != nil {
		return uuid.Nil, err
	}
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("audit: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id, err := l.append(ctx, l.q.WithTx(tx), p)
	if err != nil {
		return uuid.Nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("audit: commit: %w", err)
	}
	l.Publish(PendingEvent{ID: id, Entry: e})
	return id, nil
}

// LogTx appends an event through a caller-owned transaction. It takes the
// per-org chain lock after the caller has taken its document row lock, which is
// the global lock order used by signing state transitions. Hooks are deliberately
// deferred; call Publish with the returned value only after Commit succeeds.
func (l *Logger) LogTx(ctx context.Context, tx pgx.Tx, e Entry) (PendingEvent, error) {
	p, err := prepareEntry(e)
	if err != nil {
		return PendingEvent{}, err
	}
	id, err := l.append(ctx, l.q.WithTx(tx), p)
	if err != nil {
		return PendingEvent{}, err
	}
	return PendingEvent{ID: id, Entry: e}, nil
}

// Publish releases post-commit subscribers for an event appended by LogTx.
// It performs no database work and is safe to call only after commit.
func (l *Logger) Publish(p PendingEvent) {
	e := p.Entry
	slog.Debug("audit", "kind", e.Kind, "event_id", p.ID, "org_id", e.OrgID)
	for _, h := range l.hooks {
		h := h
		// Hooks run asynchronously with a hard per-hook timeout. The
		// audit row is the legal record; downstream subscribers (the
		// webhook fanout) are best-effort and must never block the
		// inserting caller. Detach from the caller ctx so a slow
		// subscriber doesn't ride a request-cancellation tied to the
		// HTTP handler.
		go func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("audit hook panicked", "kind", e.Kind, "panic", r)
				}
			}()
			hctx, cancel := context.WithTimeout(context.Background(), AuditHookTimeout)
			defer cancel()
			h(hctx, p.ID, e)
		}()
	}
}

// AuditHookTimeout caps a single subscriber's slot. Tunable in tests via
// the var; defaults to 5 seconds (matches the SMTP / webhook short-circuit
// behaviour everywhere else in Hash).
var AuditHookTimeout = 5 * time.Second

func uuidToPg(p *uuid.UUID) pgtype.UUID {
	if p == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *p, Valid: true}
}

func textOrNull(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}
