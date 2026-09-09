// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/magictoken"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
)

// Sentinel errors so callers can map lifecycle conflicts to the right HTTP
// status (REST) or tool error (MCP). Provider errors (eidas.GuardError,
// billing.ErrQuotaExceeded) are passed through unwrapped for the same reason.
var (
	ErrDocumentNotFound          = errors.New("document not found")
	ErrNotDraft                  = errors.New("document not in draft state")
	ErrNoSigners                 = errors.New("document needs at least one signer recipient before send")
	ErrNoRecipients              = errors.New("document needs at least one recipient before send")
	ErrNoSignatureFields         = errors.New("signature-required blocks document needs at least one signature field")
	ErrInvalidPDFSignatureField  = errors.New("signature-required PDF needs a valid placed signature field assigned to its sole signer")
	ErrMissingSignerForRole      = errors.New("a signature field has no recipient assigned to its role")
	ErrAmbiguousSignerForRole    = errors.New("a signature field role must have exactly one recipient")
	ErrEnvelopeRequiresSignature = errors.New("envelopes must require signatures")
	ErrAcknowledgementNeedsPDF   = errors.New("acknowledgement documents must be standalone PDF-source documents with a source PDF and SHA-256 digest")
	ErrAcknowledgementFields     = errors.New("acknowledgement documents cannot contain fillable fields")
	ErrUnsupportedBlockEvidence  = errors.New("block type is not supported by the immutable signing artifact")
	ErrUnsupportedBrandingLogo   = errors.New("signing does not support logo branding until immutable asset evidence is implemented")
	ErrUnresolvedVariables       = errors.New("document contains unresolved variables")
	ErrLawfulBasisUnconfirmed    = errors.New("sender must explicitly confirm the document GDPR Article 6 lawful basis")
	ErrInvalidSignerDisclosure   = errors.New("document cannot produce a valid signer privacy disclosure")
	ErrUnsafeBuiltInLegalDraft   = errors.New("document contains a withdrawn built-in legal draft revision")
	ErrAlreadyFinalised          = errors.New("document already finalised")
	ErrNotVoidable               = errors.New("only sent or in-progress documents can be voided")
	ErrEnvelopeChildLifecycle    = errors.New("envelope child lifecycle is controlled by its parent envelope")
	ErrSignatureTierUnavailable  = errors.New("AES/QES signing is unavailable until identity proof is cryptographically bound to the signature")
	ErrDraftChangedDuringSend    = errors.New("document changed while preparing send")
	ErrNotRemindable             = errors.New("document not in a remindable state")
	ErrInvalidRecipient          = errors.New("document has invalid recipient data")
	ErrUnsupportedRecipientRole  = errors.New("viewer and cc recipient workflows are unavailable in this production release")
	ErrExpiryTooSoon             = errors.New("document expiry must be at least 5 minutes in the future")
)

// MinimumExpiryLead prevents a document from entering the irreversible send
// pipeline with a signing deadline that can elapse during ordinary sealing and
// invite delivery. An omitted expiry remains valid.
const MinimumExpiryLead = 5 * time.Minute

// Actor identifies who is driving a transition. The explicit org + actor (no
// http.Request) means the worker and automatic paths use the same engine.
type Actor struct {
	UserID *uuid.UUID
	OrgID  uuid.UUID
	Email  string
	IP     string
	Via    string // "rest" | "mcp" | "worker"
	Tool   string // optional MCP tool name
	// LawfulBasis is an explicit controller instruction captured by the
	// initial send surface. A database default is never treated as consent to
	// make an Article 13 representation to the signer.
	LawfulBasis string
}

// Engine ties together the dependencies the lifecycle transitions need. The
// Resolver/EIDAS/Billing/Envelopes engines are nil-safe so unit tests + dev
// can run without them.
type Engine struct {
	Pool        *pgxpool.Pool
	Queries     *generated.Queries
	Audit       *audit.Logger
	Mailer      dispatch.Mailer
	Resolver    *resolver.Resolver
	EIDAS       *eidas.Engine
	Billing     *billing.Engine
	Envelopes   *envelopes.Engine
	Storage     EvidenceRetainer
	PublicURL   string
	OrgName     string
	Environment string
	Now         func() time.Time
}

// EvidenceRetainer is the narrow storage capability Send needs. PDF uploads
// and acknowledgement artifacts already exist before send; production must
// put them under verified Object Lock before they become legal evidence.
type EvidenceRetainer interface {
	GetVerifiedVersion(context.Context, string, string, []byte) ([]byte, error)
	ResolveVerifiedLegacy(context.Context, string, []byte) ([]byte, storage.StoredObject, error)
	RetainEvidenceVersion(context.Context, string, string, []byte, time.Time) error
}

// sourceEvidenceReader is the read half of the production storage client. It
// stays separate from EvidenceRetainer so the small retention unit fakes do
// not need to materialize a PDF unless a PDF Send is actually exercised.
type sourceEvidenceReader interface {
	GetVerifiedVersion(context.Context, string, string, []byte) ([]byte, error)
	ResolveVerifiedLegacy(context.Context, string, []byte) ([]byte, storage.StoredObject, error)
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// ValidateExpiryForSend applies the admission deadline used both by public
// send surfaces and durable sealing recovery. The caller must repeat this
// check under the document row lock before creating a sealing intent.
func ValidateExpiryForSend(expiresAt pgtype.Timestamptz, now time.Time) error {
	if !expiresAt.Valid {
		return nil
	}
	if !expiresAt.Time.After(now.Add(MinimumExpiryLead)) {
		return ErrExpiryTooSoon
	}
	return nil
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
	if e.Audit == nil {
		return SendResult{}, errors.New("send document: audit logger unavailable")
	}
	if doc.Status != "draft" {
		return SendResult{}, ErrNotDraft
	}
	if err := ValidateExpiryForSend(doc.ExpiresAt, e.now()); err != nil {
		return SendResult{}, err
	}
	if err := requireLifecycleRoot(doc); err != nil {
		return SendResult{}, err
	}
	if err := validateAcknowledgementSend(doc); err != nil {
		return SendResult{}, err
	}
	// AES/QES routing existed before either proof path was bound to the exact
	// signed digest. Advertising those tiers while accepting typed SES input is
	// a security downgrade, so reject a directly selected higher tier before
	// billing, freezing, token minting, or any lifecycle transition.
	if err := requireSupportedSignatureTier(eidas.Tier(doc.RoutingTier), eidas.TierSES); err != nil {
		return SendResult{}, err
	}
	if err := ValidateLawfulBasis(a.LawfulBasis); err != nil {
		return SendResult{}, err
	}

	if e.Billing != nil {
		if err := e.Billing.EnforceDocumentQuota(ctx, a.OrgID); err != nil {
			if errors.Is(err, billing.ErrQuotaExceeded) {
				_ = e.log(ctx, a, &doc.ID, nil, audit.KindBillingQuotaExceeded, map[string]any{"error": err.Error()})
			}
			return SendResult{}, err
		}
	}

	recs, err := e.Queries.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil {
		return SendResult{}, err
	}

	// An envelope's signing contract lives in its children, not in the empty
	// wrapper document. Load and validate the complete bundle before freezing
	// anything or minting a token. Missing envelope wiring, an empty bundle, a
	// malformed child, or a non-draft child is a hard send failure.
	var envelopeChildren []*generated.Document
	var envelopeRoles []string
	if doc.IsEnvelope {
		if e.Envelopes == nil || e.Envelopes.Q == nil {
			return SendResult{}, errors.New("send envelope: child store unavailable")
		}
		envelopeChildren, err = e.Envelopes.Children(ctx, doc.ID, doc.OrgID)
		if err != nil {
			return SendResult{}, fmt.Errorf("send envelope: list children: %w", err)
		}
		if err = validateEnvelopeChildrenStructure(doc.ID, envelopeChildren, "draft"); err != nil {
			return SendResult{}, err
		}
	}

	// Freeze variables so the snapshot captures resolved values.
	if e.Resolver != nil {
		frozen, _, ferr := e.Resolver.FreezeForSend(ctx, doc)
		if ferr != nil {
			return SendResult{}, fmt.Errorf("freeze variables: %w", ferr)
		}
		candidate := *doc
		candidate.VariablesJson = frozen
		if verr := validateResolvedBlockVariables(&candidate); verr != nil {
			return SendResult{}, verr
		}
		updated, uerr := persistFrozenDocument(ctx, e.Queries, doc, frozen)
		if uerr != nil {
			return SendResult{}, fmt.Errorf("persist frozen vars: %w", uerr)
		}
		doc = updated
	} else if verr := validateResolvedBlockVariables(doc); verr != nil {
		return SendResult{}, verr
	}

	// The wrapper does not contain the legal content. Resolve and persist every
	// child as its own immutable draft snapshot before the status transaction.
	// Envelopes fail closed if the resolver dependency is missing; silently
	// skipping a child freeze would make the signed artifact depend on live data.
	if doc.IsEnvelope {
		if e.Resolver == nil {
			return SendResult{}, errors.New("send envelope: variable resolver unavailable")
		}
		envelopeChildren, err = freezeEnvelopeChildren(ctx, e.Resolver, e.Queries, envelopeChildren)
		if err != nil {
			return SendResult{}, err
		}
		envelopeRoles, err = validateEnvelopeChildren(doc.ID, envelopeChildren)
		if err != nil {
			return SendResult{}, err
		}
	}
	if err := validateSendRecipients(doc, envelopeRoles, recs); err != nil {
		return SendResult{}, err
	}

	// eIDAS tier guard against the frozen variables.
	if e.EIDAS != nil {
		if doc.IsEnvelope {
			family := make([]*generated.Document, 0, len(envelopeChildren)+1)
			family = append(family, doc)
			family = append(family, envelopeChildren...)
			if _, gerr := guardEnvelopeEIDASSend(ctx, e.EIDAS, doc.OrgID, eidas.Tier(doc.RoutingTier), family); gerr != nil {
				return SendResult{}, gerr
			}
		} else {
			evalInput, ierr := BuildEIDASEvaluateInput(doc)
			if ierr != nil {
				return SendResult{}, fmt.Errorf("build eIDAS evaluation input: %w", ierr)
			}
			decision, gerr := e.EIDAS.Evaluate(ctx, doc.OrgID, evalInput)
			if gerr != nil {
				return SendResult{}, gerr
			}
			if gerr := enforceEIDASSendDecision(eidas.Tier(doc.RoutingTier), decision); gerr != nil {
				return SendResult{}, gerr
			}
		}
	}
	preparedPDFPageCount, err := inspectSendSourcePDF(ctx, e.Storage, doc)
	if err != nil {
		return SendResult{}, err
	}

	preparedDoc := doc

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
	if err := verifyPreparedSendDocument(preparedDoc, lockedDoc); err != nil {
		return SendResult{}, err
	}
	if err := requireLifecycleRoot(lockedDoc); err != nil {
		return SendResult{}, err
	}
	if err := validateAcknowledgementSend(lockedDoc); err != nil {
		return SendResult{}, err
	}
	doc = lockedDoc

	// Lock and re-check every prepared child while the parent is locked. The
	// envelope topology queries take the same parent lock, so membership cannot
	// change after this point. Comparing the prepared bytes also catches an edit
	// that raced the preflight/freeze and prevents signing an unvalidated tree.
	if doc.IsEnvelope {
		listed, lerr := q.ListEnvelopeChildren(ctx, generated.ListEnvelopeChildrenParams{
			ParentEnvelopeID: pgtype.UUID{Bytes: doc.ID, Valid: true},
			OrgID:            doc.OrgID,
		})
		if lerr != nil {
			return SendResult{}, fmt.Errorf("send envelope: re-list children: %w", lerr)
		}
		lockedChildren := make([]*generated.Document, 0, len(listed))
		for _, listedChild := range listed {
			lockedChild, lerr := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{
				ID: listedChild.ID, OrgID: doc.OrgID,
			})
			if lerr != nil {
				return SendResult{}, fmt.Errorf("send envelope: lock child %s: %w", listedChild.ID, lerr)
			}
			lockedChildren = append(lockedChildren, lockedChild)
		}
		roles, verr := validateEnvelopeChildren(doc.ID, lockedChildren)
		if verr != nil {
			return SendResult{}, verr
		}
		if verr := verifyPreparedEnvelopeChildren(envelopeChildren, lockedChildren); verr != nil {
			return SendResult{}, verr
		}
		envelopeChildren = lockedChildren
		envelopeRoles = roles
	}

	// Recipient CRUD shares this parent row lock. Re-list only after acquiring
	// it, then validate and mint exclusively from this stable snapshot; the
	// earlier list is advisory preflight and cannot authorize a ceremony.
	lockedRecipients, err := q.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil {
		return SendResult{}, fmt.Errorf("send document: re-list recipients: %w", err)
	}
	if err := validateSendRecipients(doc, envelopeRoles, lockedRecipients); err != nil {
		return SendResult{}, err
	}
	if doc.SourceKind == "pdf" {
		fields, ferr := q.ListFieldsByDocument(ctx, doc.ID)
		if ferr != nil {
			return SendResult{}, fmt.Errorf("send PDF: list fields: %w", ferr)
		}
		if doc.RequiresSignature {
			if ferr := validatePDFSignatureFields(doc, lockedRecipients, fields, preparedPDFPageCount); ferr != nil {
				return SendResult{}, ferr
			}
		} else if ferr := validateAcknowledgementFields(fields); ferr != nil {
			return SendResult{}, ferr
		}
	}
	confirmedBy := pgtype.UUID{}
	if a.UserID != nil {
		confirmedBy = pgtype.UUID{Bytes: *a.UserID, Valid: true}
	}
	confirmation, err := q.ConfirmDocumentLawfulBasis(ctx, generated.ConfirmDocumentLawfulBasisParams{
		DocumentID: doc.ID, OrgID: doc.OrgID, LawfulBasis: strings.TrimSpace(a.LawfulBasis),
		ConfirmedBy: confirmedBy, Via: a.Via,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SendResult{}, ErrDraftChangedDuringSend
		}
		return SendResult{}, fmt.Errorf("confirm document lawful basis: %w", err)
	}
	confirmedDoc := *doc
	confirmedDoc.LawfulBasis = confirmation.LawfulBasis
	if err := requireConfirmedLawfulBasis(&confirmedDoc, confirmation); err != nil {
		return SendResult{}, err
	}
	doc = &confirmedDoc
	if err := requireValidSignerDisclosure(doc, confirmation); err != nil {
		return SendResult{}, err
	}
	// The unlocked preflight above can perform storage and resolver work. Check
	// the persisted deadline again while holding the document lock, immediately
	// before committing the durable/possibly irreversible sealing intent.
	if err := ValidateExpiryForSend(doc.ExpiresAt, e.now()); err != nil {
		return SendResult{}, err
	}
	// Resolve and persist the complete effective theme while the document rows
	// are locked and before any irreversible lifecycle transition. Later org
	// branding changes cannot alter signer or terminal rendering. Envelope
	// children get complete snapshots too, even though the current renderer uses
	// the root theme, so their independent evidence state remains self-contained.
	brandingDocs := append([]*generated.Document{doc}, envelopeChildren...)
	for _, brandingDoc := range brandingDocs {
		logoURL, ferr := freezeDocumentBranding(ctx, tx, brandingDoc)
		if ferr != nil {
			return SendResult{}, ferr
		}
		if logoURL != "" {
			return SendResult{}, ErrUnsupportedBrandingLogo
		}
	}
	// Durable cross-system boundary: commit a non-editable/non-deletable
	// `sealing` state and actor intent before applying irreversible Object Lock.
	// A crash or SQL commit failure after retention therefore leaves a resumable
	// sealing ceremony, never an ordinary draft containing seven-year WORM PII.
	actorUserID := pgtype.UUID{}
	if a.UserID != nil {
		actorUserID = pgtype.UUID{Bytes: *a.UserID, Valid: true}
	}
	if _, err := q.CreateSendSealingIntent(ctx, generated.CreateSendSealingIntentParams{
		DocumentID: doc.ID, OrgID: doc.OrgID, ActorUserID: actorUserID,
		ActorEmail: a.Email, ActorIp: a.IP, Via: a.Via, Tool: a.Tool,
	}); err != nil {
		return SendResult{}, fmt.Errorf("create send sealing intent: %w", err)
	}
	if doc.IsEnvelope {
		sealedChildren, serr := q.BeginEnvelopeChildrenSendSealing(ctx, generated.BeginEnvelopeChildrenSendSealingParams{
			ParentEnvelopeID: pgtype.UUID{Bytes: doc.ID, Valid: true}, OrgID: doc.OrgID,
		})
		if serr != nil {
			return SendResult{}, fmt.Errorf("seal envelope children: %w", serr)
		}
		if len(sealedChildren) != len(envelopeChildren) {
			return SendResult{}, fmt.Errorf("seal envelope children: updated %d of %d", len(sealedChildren), len(envelopeChildren))
		}
	}
	if _, err := q.BeginDocumentSendSealing(ctx, generated.BeginDocumentSendSealingParams{ID: doc.ID, OrgID: doc.OrgID}); err != nil {
		return SendResult{}, fmt.Errorf("begin document send sealing: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return SendResult{}, fmt.Errorf("commit send sealing intent: %w", err)
	}
	return e.ResumeSendSealing(ctx, doc.ID, doc.OrgID)
}

type sealedSendSnapshot struct {
	doc           *generated.Document
	children      []*generated.Document
	envelopeRoles []string
	recipients    []*generated.Recipient
	fields        []*generated.DocumentField
	pageCount     int
}

type pendingInvite struct {
	recID                     uuid.UUID
	email, name, role, locale string
	signURL, beaconURL        string
}

// ResumeSendSealing is the synchronous and worker recovery path for the
// durable draft -> sealing -> sent transition. It is safe to call repeatedly:
// retention is idempotent, the retained marker is durable, and the final row
// lock permits exactly one token/outbox/audit commit.
func (e *Engine) ResumeSendSealing(ctx context.Context, docID, orgID uuid.UUID) (SendResult, error) {
	if e == nil || e.Pool == nil || e.Queries == nil || e.Audit == nil {
		return SendResult{}, errors.New("resume send sealing: lifecycle store unavailable")
	}
	intent, err := e.Queries.GetSendSealingIntent(ctx, generated.GetSendSealingIntentParams{
		DocumentID: docID, OrgID: orgID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return e.completedSendSealingResult(ctx, docID, orgID)
	}
	if err != nil {
		return SendResult{}, fmt.Errorf("resume send sealing: load intent: %w", err)
	}
	intent, err = e.ensureSendSealingRetainUntil(ctx, intent)
	if err != nil {
		e.recordSendSealingFailure(ctx, docID, orgID, err)
		return SendResult{}, err
	}
	snapshot, err := e.loadSealedSendSnapshot(ctx, docID, orgID)
	if err != nil {
		if sendSealingReversible(intent) {
			if abortErr := e.abortUnstartedSendSealing(ctx, docID, orgID); abortErr != nil {
				return SendResult{}, errors.Join(err, fmt.Errorf("abort invalid pre-retention sealing intent: %w", abortErr))
			}
		}
		e.recordSendSealingFailure(ctx, docID, orgID, err)
		return SendResult{}, err
	}
	if sendSealingReversible(intent) {
		// A pre-retention intent is still safe to unwind. Never cross the Object
		// Lock boundary when the original absolute signing deadline no longer has
		// the normal admission margin. If another worker starts retention between
		// this check and the abort, reload and continue as irreversible recovery.
		if expiryErr := ValidateExpiryForSend(snapshot.doc.ExpiresAt, e.now()); expiryErr != nil {
			if abortErr := e.abortUnstartedSendSealing(ctx, docID, orgID); abortErr == nil {
				return SendResult{}, expiryErr
			} else {
				reloaded, reloadErr := e.Queries.GetSendSealingIntent(ctx, generated.GetSendSealingIntentParams{
					DocumentID: docID, OrgID: orgID,
				})
				if reloadErr != nil {
					return SendResult{}, errors.Join(expiryErr, abortErr, reloadErr)
				}
				if sendSealingReversible(reloaded) {
					return SendResult{}, errors.Join(expiryErr, abortErr)
				}
				intent = reloaded
			}
		}
	}
	if !intent.RetentionCompletedAt.Valid {
		rows, err := e.Queries.MarkSendSealingRetentionStarted(ctx, generated.MarkSendSealingRetentionStartedParams{
			DocumentID: docID, OrgID: orgID,
		})
		if err != nil {
			return SendResult{}, fmt.Errorf("resume send sealing: persist retention start: %w", err)
		}
		if rows != 1 {
			// Another recovery worker can finish retention after our initial
			// intent read but before this idempotent marker update. Distinguish
			// that successful handoff from a genuinely invalid/disappeared
			// intent instead of failing a concurrent automation replay.
			reloaded, reloadErr := e.reloadCompletedSendSealingIntent(ctx, docID, orgID)
			if errors.Is(reloadErr, pgx.ErrNoRows) {
				return e.completedSendSealingResult(ctx, docID, orgID)
			}
			if reloadErr != nil {
				return SendResult{}, fmt.Errorf("resume send sealing: retention-start handoff: %w", reloadErr)
			}
			intent = reloaded
		}
		if !intent.RetentionCompletedAt.Valid {
			if err := retainReadySendEvidence(ctx, e.Storage, snapshot.doc, snapshot.recipients, snapshot.fields, snapshot.pageCount, intent.RetainUntil.Time); err != nil {
				e.recordSendSealingFailure(ctx, docID, orgID, err)
				return SendResult{}, fmt.Errorf("resume send sealing: retain evidence: %w", err)
			}
			for _, child := range snapshot.children {
				if err := retainSendEvidence(ctx, e.Storage, child, intent.RetainUntil.Time); err != nil {
					e.recordSendSealingFailure(ctx, docID, orgID, err)
					return SendResult{}, fmt.Errorf("resume send envelope: retain child evidence: %w", err)
				}
			}
			rows, err = e.Queries.MarkSendSealingRetentionComplete(ctx, generated.MarkSendSealingRetentionCompleteParams{
				DocumentID: docID, OrgID: orgID,
			})
			if err != nil {
				return SendResult{}, fmt.Errorf("resume send sealing: persist retained marker: %w", err)
			}
			if rows != 1 {
				if _, reloadErr := e.reloadCompletedSendSealingIntent(ctx, docID, orgID); errors.Is(reloadErr, pgx.ErrNoRows) {
					return e.completedSendSealingResult(ctx, docID, orgID)
				} else if reloadErr != nil {
					return SendResult{}, fmt.Errorf("resume send sealing: retained-marker handoff: %w", reloadErr)
				}
			}
		}
	}
	return e.completeSealedSend(ctx, snapshot)
}

// reloadCompletedSendSealingIntent closes the marker race between concurrent
// recovery workers. An existing row is accepted only when its immutable
// retention commitment is valid and the retained marker is already durable.
// The caller handles pgx.ErrNoRows by reconciling the authoritative document:
// a winning worker deletes the intent in the same transaction that completes
// the sealing transition.
func (e *Engine) reloadCompletedSendSealingIntent(ctx context.Context, docID, orgID uuid.UUID) (*generated.SendSealingIntent, error) {
	intent, err := e.Queries.GetSendSealingIntent(ctx, generated.GetSendSealingIntentParams{
		DocumentID: docID, OrgID: orgID,
	})
	if err != nil {
		return nil, err
	}
	if _, err := canonicalSendSealingRetainUntil(intent); err != nil {
		return nil, err
	}
	if !intent.RetentionCompletedAt.Valid {
		return nil, errors.New("retention intent did not complete during concurrent handoff")
	}
	return intent, nil
}

// completedSendSealingResult makes recovery convergent after another worker
// atomically completes the document and consumes its intent. Signing links are
// deliberately not reconstructed from stored token hashes; callers receive the
// authoritative lifecycle status and the winning transaction remains the sole
// publisher of invitations and audit events.
func (e *Engine) completedSendSealingResult(ctx context.Context, docID, orgID uuid.UUID) (SendResult, error) {
	doc, err := e.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: docID, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return SendResult{}, ErrDocumentNotFound
	}
	if err != nil {
		return SendResult{}, fmt.Errorf("resume send sealing: reconcile completed document: %w", err)
	}
	if result, ok := completedSendSealingStatus(doc); ok {
		return result, nil
	}
	return SendResult{}, fmt.Errorf("resume send sealing: intent unavailable while document status is %s: %w", doc.Status, ErrNotDraft)
}

func completedSendSealingStatus(doc *generated.Document) (SendResult, bool) {
	if doc == nil || !doc.EvidenceVersionPinsRequired ||
		!doc.SentAt.Valid || doc.SentAt.Time.IsZero() ||
		!doc.Article13NoticeEpochAt.Valid ||
		!doc.Article13NoticeEpochAt.Time.Equal(doc.SentAt.Time) ||
		!article13.IsSupportedSchema(doc.Article13NoticeSchema) ||
		!doc.Article13NoticeEpochV61Committed {
		return SendResult{}, false
	}
	if _, err := article13.CanonicalSentAt(doc.SentAt.Time); err != nil {
		return SendResult{}, false
	}
	switch doc.Status {
	case "sent", "in_progress", "changes_requested", "finalizing", "completed", "declined", "voided", "expired":
		return SendResult{Status: doc.Status}, true
	default:
		return SendResult{}, false
	}
}

func (e *Engine) ensureSendSealingRetainUntil(ctx context.Context, intent *generated.SendSealingIntent) (*generated.SendSealingIntent, error) {
	if e == nil || e.Queries == nil || intent == nil {
		return nil, errors.New("resume send sealing: retention deadline dependencies unavailable")
	}
	// Migration 00061 rejects every pre-control intent. New intents must already
	// carry the database-pinned ceremony epoch and its exact deadline before the
	// first S3 mutation; never synthesize either value from an application clock
	// or a retention-attempt timestamp on recovery.
	if _, err := canonicalSendSealingRetainUntil(intent); err != nil {
		return nil, fmt.Errorf("resume send sealing: %w", err)
	}
	reloaded, err := e.Queries.GetSendSealingIntent(ctx, generated.GetSendSealingIntentParams{
		DocumentID: intent.DocumentID,
		OrgID:      intent.OrgID,
	})
	if err != nil {
		return nil, fmt.Errorf("resume send sealing: reload retention commitment: %w", err)
	}
	if _, err := canonicalSendSealingRetainUntil(reloaded); err != nil {
		return nil, fmt.Errorf("resume send sealing: %w", err)
	}
	if reloaded.DocumentID != intent.DocumentID || reloaded.OrgID != intent.OrgID ||
		!reloaded.Article13NoticeEpochAt.Time.Equal(intent.Article13NoticeEpochAt.Time) ||
		!reloaded.RetainUntil.Time.Equal(intent.RetainUntil.Time) {
		return nil, errors.New("resume send sealing: immutable retention commitment changed during reload")
	}
	return reloaded, nil
}

func canonicalSendSealingRetainUntil(intent *generated.SendSealingIntent) (time.Time, error) {
	if intent == nil || !intent.Article13NoticeEpochAt.Valid || intent.Article13NoticeEpochAt.Time.IsZero() {
		return time.Time{}, errors.New("persisted Article 13 ceremony epoch is unavailable")
	}
	if !intent.RetainUntil.Valid || intent.RetainUntil.Time.IsZero() {
		return time.Time{}, errors.New("persisted retention deadline is unavailable")
	}
	canonical := intent.RetainUntil.Time.UTC()
	if canonical.Nanosecond() != 0 {
		return time.Time{}, errors.New("persisted retention deadline must use whole-second precision")
	}
	want := storage.EvidenceRetentionDeadline(intent.Article13NoticeEpochAt.Time, article13.RetentionYearsV1)
	if !canonical.Equal(want) {
		return time.Time{}, fmt.Errorf(
			"persisted retention deadline %s does not match Article 13 ceremony epoch commitment %s",
			canonical.Format(time.RFC3339), want.Format(time.RFC3339),
		)
	}
	return canonical, nil
}

// abortUnstartedSendSealing is deliberately available only before the durable
// retention-start marker. Once retention may have touched Object Lock, no code
// path may represent the document as an ordinary deletable draft again.
func (e *Engine) abortUnstartedSendSealing(ctx context.Context, docID, orgID uuid.UUID) error {
	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)
	doc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: docID, OrgID: orgID})
	if err != nil {
		return err
	}
	// Lock order is document -> intent, matching completion. The intent lock
	// makes this recheck mutually exclusive with MarkSendSealingRetentionStarted;
	// otherwise another worker could begin Object Lock between the read and the
	// unconditional draft rollback/delete below.
	intent, err := q.GetSendSealingIntentForUpdate(ctx, generated.GetSendSealingIntentForUpdateParams{DocumentID: docID, OrgID: orgID})
	if err != nil {
		return err
	}
	if !sendSealingReversible(intent) {
		return errors.New("retention already started; sealing state is not reversible")
	}
	if doc.Status != "sealing" {
		return fmt.Errorf("document status is %s, want sealing", doc.Status)
	}
	if doc.IsEnvelope {
		if _, err := q.AbortEnvelopeChildrenSendSealing(ctx, generated.AbortEnvelopeChildrenSendSealingParams{
			ParentEnvelopeID: pgtype.UUID{Bytes: doc.ID, Valid: true}, OrgID: doc.OrgID,
		}); err != nil {
			return err
		}
	}
	rows, err := q.AbortDocumentSendSealing(ctx, generated.AbortDocumentSendSealingParams{ID: doc.ID, OrgID: doc.OrgID})
	if err != nil || rows != 1 {
		return fmt.Errorf("abort document sealing: rows=%d err=%w", rows, err)
	}
	rows, err = q.DeleteSendSealingIntent(ctx, generated.DeleteSendSealingIntentParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil || rows != 1 {
		return fmt.Errorf("delete aborted sealing intent: rows=%d err=%w", rows, err)
	}
	return tx.Commit(ctx)
}

func sendSealingReversible(intent *generated.SendSealingIntent) bool {
	return intent != nil && !intent.RetentionStartedAt.Valid && !intent.RetentionCompletedAt.Valid
}

func (e *Engine) recordSendSealingFailure(ctx context.Context, docID, orgID uuid.UUID, cause error) {
	if e == nil || e.Queries == nil || cause == nil {
		return
	}
	_, _ = e.Queries.MarkSendSealingAttemptFailed(ctx, generated.MarkSendSealingAttemptFailedParams{
		DocumentID: docID, OrgID: orgID,
		LastError: pgtype.Text{String: truncateString(cause.Error(), 1000), Valid: true},
	})
}

func (e *Engine) loadSealedSendSnapshot(ctx context.Context, docID, orgID uuid.UUID) (*sealedSendSnapshot, error) {
	doc, err := e.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: docID, OrgID: orgID})
	if err != nil {
		return nil, fmt.Errorf("resume send sealing: load document: %w", err)
	}
	if doc.Status != "sealing" {
		return nil, fmt.Errorf("resume send sealing: document status is %s, want sealing", doc.Status)
	}
	if err := requireLifecycleRoot(doc); err != nil {
		return nil, err
	}
	if err := validateAcknowledgementSend(doc); err != nil {
		return nil, err
	}
	if err := requireSupportedSignatureTier(eidas.Tier(doc.RoutingTier), eidas.TierSES); err != nil {
		return nil, err
	}
	confirmation, err := e.Queries.GetDocumentLawfulBasisConfirmation(ctx, generated.GetDocumentLawfulBasisConfirmationParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil {
		return nil, fmt.Errorf("resume send sealing: load lawful-basis confirmation: %w", err)
	}
	if err := requireConfirmedLawfulBasis(doc, confirmation); err != nil {
		return nil, fmt.Errorf("resume send sealing: %w", err)
	}
	if err := requireValidSignerDisclosure(doc, confirmation); err != nil {
		return nil, fmt.Errorf("resume send sealing: %w", err)
	}
	// Validate signer-visible disclosure before resolving source versions or
	// touching the durable retention-start marker. A pre-cutover reversible
	// sealing intent can therefore return safely to draft on invalid authoring
	// data without any retention-side effect.
	doc, err = e.pinSendEvidenceVersions(ctx, doc)
	if err != nil {
		return nil, err
	}

	snapshot := &sealedSendSnapshot{doc: doc}
	if doc.IsEnvelope {
		if e.Envelopes == nil || e.Envelopes.Q == nil {
			return nil, errors.New("resume send envelope: child store unavailable")
		}
		snapshot.children, err = e.Envelopes.Children(ctx, doc.ID, doc.OrgID)
		if err != nil {
			return nil, fmt.Errorf("resume send envelope: list children: %w", err)
		}
		for i, child := range snapshot.children {
			pinned, pinErr := e.pinSendEvidenceVersions(ctx, child)
			if pinErr != nil {
				return nil, fmt.Errorf("resume send envelope: pin child evidence VersionIds: %w", pinErr)
			}
			snapshot.children[i] = pinned
		}
		snapshot.envelopeRoles, err = validateEnvelopeChildrenForStatus(doc.ID, snapshot.children, "sealing")
		if err != nil {
			return nil, err
		}
	}
	// Sealing intents can outlive the process version that created them. Re-run
	// the unresolved-variable guard on the durable frozen snapshot so a worker
	// cannot resume a pre-guard intent and certify literal contract tokens. Once
	// retention has started the caller deliberately leaves an invalid intent
	// fail-closed for operator recovery rather than promoting it to sent.
	if err := validateResolvedSealedSnapshot(doc, snapshot.children); err != nil {
		return nil, err
	}
	snapshot.recipients, err = e.Queries.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil {
		return nil, fmt.Errorf("resume send sealing: list recipients: %w", err)
	}
	if err := validateSendRecipients(doc, snapshot.envelopeRoles, snapshot.recipients); err != nil {
		return nil, err
	}

	if e.EIDAS != nil {
		if doc.IsEnvelope {
			family := make([]*generated.Document, 0, len(snapshot.children)+1)
			family = append(family, doc)
			family = append(family, snapshot.children...)
			if _, err := guardEnvelopeEIDASSend(ctx, e.EIDAS, doc.OrgID, eidas.Tier(doc.RoutingTier), family); err != nil {
				return nil, err
			}
		} else {
			input, err := BuildEIDASEvaluateInput(doc)
			if err != nil {
				return nil, fmt.Errorf("resume send sealing: build eIDAS input: %w", err)
			}
			decision, err := e.EIDAS.Evaluate(ctx, doc.OrgID, input)
			if err != nil {
				return nil, err
			}
			if err := enforceEIDASSendDecision(eidas.Tier(doc.RoutingTier), decision); err != nil {
				return nil, err
			}
		}
	}
	snapshot.pageCount, err = inspectSendSourcePDF(ctx, e.Storage, doc)
	if err != nil {
		return nil, err
	}
	if doc.SourceKind == "pdf" {
		snapshot.fields, err = e.Queries.ListFieldsByDocument(ctx, doc.ID)
		if err != nil {
			return nil, fmt.Errorf("resume send PDF: list fields: %w", err)
		}
		if doc.RequiresSignature {
			if err := validatePDFSignatureFields(doc, snapshot.recipients, snapshot.fields, snapshot.pageCount); err != nil {
				return nil, err
			}
		} else if err := validateAcknowledgementFields(snapshot.fields); err != nil {
			return nil, err
		}
	}
	return snapshot, nil
}

func (e *Engine) completeSealedSend(ctx context.Context, prepared *sealedSendSnapshot) (SendResult, error) {
	if prepared == nil || prepared.doc == nil {
		return SendResult{}, errors.New("complete send sealing: prepared snapshot unavailable")
	}
	docID, orgID := prepared.doc.ID, prepared.doc.OrgID
	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return SendResult{}, fmt.Errorf("complete send sealing: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)
	doc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: docID, OrgID: orgID})
	if err != nil {
		return SendResult{}, fmt.Errorf("complete send sealing: lock document: %w", err)
	}
	if doc.Status != "sealing" {
		if result, ok := completedSendSealingStatus(doc); ok {
			return result, nil
		}
		return SendResult{}, fmt.Errorf("complete send sealing: document status is %s, want sealing", doc.Status)
	}
	// Lock order is document -> intent, matching reversible abort. It also
	// makes a concurrent loser wait for the winning completion transaction and
	// validate its durable proof above instead of observing a stale phase.
	intent, err := q.GetSendSealingIntentForUpdate(ctx, generated.GetSendSealingIntentForUpdateParams{DocumentID: docID, OrgID: orgID})
	if err != nil {
		return SendResult{}, fmt.Errorf("complete send sealing: lock intent: %w", err)
	}
	if !intent.RetentionCompletedAt.Valid {
		return SendResult{}, errors.New("complete send sealing: evidence retention is not durable")
	}
	retentionDeadline, err := canonicalSendSealingRetainUntil(intent)
	if err != nil {
		return SendResult{}, fmt.Errorf("complete send sealing: %w", err)
	}
	retainUntil := retentionDeadline.Format(time.RFC3339)
	confirmation, err := q.GetDocumentLawfulBasisConfirmation(ctx, generated.GetDocumentLawfulBasisConfirmationParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil {
		return SendResult{}, fmt.Errorf("complete send sealing: load lawful-basis confirmation: %w", err)
	}
	if err := requireConfirmedLawfulBasis(doc, confirmation); err != nil {
		return SendResult{}, fmt.Errorf("complete send sealing: %w", err)
	}
	if err := verifyPreparedSealedDocument(prepared.doc, doc); err != nil {
		return SendResult{}, err
	}

	var children []*generated.Document
	var envelopeRoles []string
	if doc.IsEnvelope {
		listed, err := q.ListEnvelopeChildren(ctx, generated.ListEnvelopeChildrenParams{
			ParentEnvelopeID: pgtype.UUID{Bytes: doc.ID, Valid: true}, OrgID: doc.OrgID,
		})
		if err != nil {
			return SendResult{}, fmt.Errorf("complete send envelope: re-list children: %w", err)
		}
		for _, listedChild := range listed {
			child, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: listedChild.ID, OrgID: doc.OrgID})
			if err != nil {
				return SendResult{}, fmt.Errorf("complete send envelope: lock child %s: %w", listedChild.ID, err)
			}
			children = append(children, child)
		}
		envelopeRoles, err = validateEnvelopeChildrenForStatus(doc.ID, children, "sealing")
		if err != nil {
			return SendResult{}, err
		}
		if err := verifyPreparedEnvelopeChildren(prepared.children, children); err != nil {
			return SendResult{}, err
		}
	}

	recipients, err := q.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil {
		return SendResult{}, fmt.Errorf("complete send sealing: list recipients: %w", err)
	}
	if err := validateSendRecipients(doc, envelopeRoles, recipients); err != nil {
		return SendResult{}, err
	}
	if doc.SourceKind == "pdf" {
		fields, err := q.ListFieldsByDocument(ctx, doc.ID)
		if err != nil {
			return SendResult{}, fmt.Errorf("complete send PDF: list fields: %w", err)
		}
		if doc.RequiresSignature {
			if err := validatePDFSignatureFields(doc, recipients, fields, prepared.pageCount); err != nil {
				return SendResult{}, err
			}
		} else if err := validateAcknowledgementFields(fields); err != nil {
			return SendResult{}, err
		}
	}
	expiredAtDatabaseNow, err := q.IsSendSealingExpired(ctx, generated.IsSendSealingExpiredParams{
		ID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil {
		return SendResult{}, fmt.Errorf("complete send sealing: inspect expiry: %w", err)
	}
	expiredBeforeInvite := expiredAtDatabaseNow.Valid && expiredAtDatabaseNow.Bool

	a := actorFromSendSealingIntent(intent)
	exp := magictoken.Expiry(doc.ExpiresAt, e.now())
	out := SendResult{Status: "sent", Links: make([]SignLink, 0, len(recipients))}
	invites := make([]pendingInvite, 0, len(recipients))
	if !expiredBeforeInvite {
		for _, rec := range recipients {
			tok, err := e.rotateToken(ctx, q, rec.ID, doc.ID, exp)
			if err != nil {
				return SendResult{}, err
			}
			rows, err := q.MarkRecipientSent(ctx, generated.MarkRecipientSentParams{ID: rec.ID, DocumentID: doc.ID})
			if err != nil {
				return SendResult{}, fmt.Errorf("complete send sealing: mark recipient sent: %w", err)
			}
			if rows != 1 {
				return SendResult{}, fmt.Errorf("complete send sealing: mark recipient %s sent: updated %d rows", rec.ID, rows)
			}
			signURL := e.PublicURL + "/sign/" + tok
			beaconURL := e.PublicURL + "/e/o/" + tok
			out.Links = append(out.Links, SignLink{RecipientID: rec.ID, Email: rec.Email, Name: rec.Name, Role: rec.Role, URL: signURL})
			invites = append(invites, pendingInvite{rec.ID, rec.Email, rec.Name, rec.Role, rec.Locale, signURL, beaconURL})
		}
	}
	sentDocument, err := q.CompleteDocumentSendSealing(ctx, generated.CompleteDocumentSendSealingParams{ID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return SendResult{}, fmt.Errorf("complete document send sealing: %w", err)
	}
	if sentDocument == nil || sentDocument.ID != doc.ID || sentDocument.OrgID != doc.OrgID || sentDocument.Status != "sent" {
		return SendResult{}, errors.New("complete document send sealing returned invalid state")
	}
	doc = sentDocument
	var sentChildren []*generated.Document
	if doc.IsEnvelope {
		updated, err := q.CompleteEnvelopeChildrenSendSealing(ctx, generated.CompleteEnvelopeChildrenSendSealingParams{
			ParentEnvelopeID: pgtype.UUID{Bytes: doc.ID, Valid: true}, OrgID: doc.OrgID,
		})
		if err != nil {
			return SendResult{}, fmt.Errorf("complete envelope child send sealing: %w", err)
		}
		if len(updated) != len(children) {
			return SendResult{}, fmt.Errorf("complete envelope child send sealing: updated %d of %d", len(updated), len(children))
		}
		for _, child := range updated {
			if child == nil || child.Status != "sent" {
				return SendResult{}, errors.New("complete envelope child send sealing returned invalid state")
			}
			sentChildren = append(sentChildren, child)
		}
	}

	if !expiredBeforeInvite {
		if err := q.UpsertReminderSchedule(ctx, generated.UpsertReminderScheduleParams{
			DocumentID: doc.ID, Column2: []byte(`[{"days_after_send":3},{"days_after_send":7}]`), FiresRemaining: 2,
		}); err != nil {
			return SendResult{}, fmt.Errorf("complete send sealing: reminder schedule: %w", err)
		}
	}
	queueBacked := usesDurableEmailQueue(e.Mailer)
	if queueBacked {
		messages := make([]dispatch.Message, 0, len(invites))
		for _, inv := range invites {
			msg, err := e.renderEmail(dispatch.KindInvite, inv.email, inv.name, doc.Name, a.Email, inv.signURL, inv.beaconURL, inv.locale, doc.RequiresSignature)
			if err != nil {
				return SendResult{}, fmt.Errorf("complete send sealing: render invite: %w", err)
			}
			messages = append(messages, msg)
		}
		if err := enqueueLifecycleEmails(ctx, q, messages); err != nil {
			return SendResult{}, fmt.Errorf("complete send sealing: persist invite outbox: %w", err)
		}
	}

	auditEntries := make([]audit.Entry, 0, len(invites)+(2*len(sentChildren))+2)
	for i := range invites {
		inv := &invites[i]
		auditEntries = append(auditEntries, e.auditEntry(a, &doc.ID, &inv.recID, audit.KindRecipientInvited, map[string]any{
			"email": inv.email, "role": inv.role,
		}))
	}
	for _, child := range sentChildren {
		payload := map[string]any{
			"envelope_id": doc.ID.String(), "propagated": true, "retain_until": retainUntil,
		}
		if expiredBeforeInvite {
			payload["expired_before_invite"] = true
		}
		entry, err := e.documentSentAuditEntry(a, child, payload)
		if err != nil {
			return SendResult{}, fmt.Errorf("complete envelope child send sealing: audit epoch: %w", err)
		}
		auditEntries = append(auditEntries, entry)
	}
	sentPayload := map[string]any{
		"recipient_count": len(out.Links), "evidence_retained": true,
		"lawful_basis": doc.LawfulBasis, "lawful_basis_confirmed": true,
		"retain_until": retainUntil,
	}
	if expiredBeforeInvite {
		sentPayload["expired_before_invite"] = true
	}
	sentEntry, err := e.documentSentAuditEntry(a, doc, sentPayload)
	if err != nil {
		return SendResult{}, fmt.Errorf("complete document send sealing: audit epoch: %w", err)
	}
	auditEntries = append(auditEntries, sentEntry)
	if expiredBeforeInvite {
		// Retention may already have touched external Object Lock, so reverting
		// to draft would misrepresent immutable evidence. Complete the sealed
		// epoch and expire it in this same transaction: no sent state is externally
		// visible, no invite/reminder is queued, and no born-expired link escapes.
		expiredDocument, expireErr := q.ExpireDocumentIfActive(ctx, generated.ExpireDocumentIfActiveParams{
			ID: doc.ID, OrgID: doc.OrgID,
		})
		if expireErr != nil {
			return SendResult{}, fmt.Errorf("complete expired send sealing: expire document: %w", expireErr)
		}
		if expiredDocument == nil || expiredDocument.Status != "expired" {
			return SendResult{}, errors.New("complete expired send sealing returned invalid document state")
		}
		expiredChildIDs, expireErr := expireLockedEnvelopeChildren(ctx, q, sentChildren)
		if expireErr != nil {
			return SendResult{}, fmt.Errorf("complete expired send sealing: %w", expireErr)
		}
		if len(expiredChildIDs) != len(sentChildren) {
			return SendResult{}, fmt.Errorf("complete expired send sealing: expired %d of %d envelope children", len(expiredChildIDs), len(sentChildren))
		}
		artifactIDs := make([]uuid.UUID, 0, len(expiredChildIDs)+1)
		artifactIDs = append(artifactIDs, doc.ID)
		artifactIDs = append(artifactIDs, expiredChildIDs...)
		for _, artifactID := range artifactIDs {
			if err := q.InvalidateRecipientTokens(ctx, artifactID); err != nil {
				return SendResult{}, fmt.Errorf("complete expired send sealing: invalidate recipient tokens: %w", err)
			}
			if err := q.CancelReminder(ctx, artifactID); err != nil {
				return SendResult{}, fmt.Errorf("complete expired send sealing: cancel reminder: %w", err)
			}
		}
		auditEntries = append(auditEntries, audit.Entry{
			OrgID: doc.OrgID, DocumentID: &doc.ID, Kind: audit.KindDocumentExpired,
			Payload: map[string]any{"before_invite": true, "irreversible_sealing_recovery": true},
		})
		for _, childID := range expiredChildIDs {
			childID := childID
			auditEntries = append(auditEntries, audit.Entry{
				OrgID: doc.OrgID, DocumentID: &childID, Kind: audit.KindDocumentExpired,
				Payload: map[string]any{
					"envelope_id": doc.ID.String(), "propagated": true,
					"before_invite": true, "irreversible_sealing_recovery": true,
				},
			})
		}
		out.Status = "expired"
		out.Links = nil
	}
	pendingAudits, err := appendAuditEntriesTx(ctx, e.Audit, tx, auditEntries)
	if err != nil {
		return SendResult{}, fmt.Errorf("complete send sealing: audit send: %w", err)
	}
	rows, err := q.DeleteSendSealingIntent(ctx, generated.DeleteSendSealingIntentParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil || rows != 1 {
		return SendResult{}, fmt.Errorf("complete send sealing: delete intent: rows=%d err=%w", rows, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return SendResult{}, fmt.Errorf("complete send sealing: commit sent state: %w", err)
	}
	for _, pending := range pendingAudits {
		e.Audit.Publish(pending)
	}
	if !queueBacked && !expiredBeforeInvite {
		for _, inv := range invites {
			e.sendEmail(dispatch.KindInvite, inv.email, inv.name, doc.Name, a.Email, inv.signURL, inv.beaconURL, inv.locale, doc.RequiresSignature)
		}
	}
	return out, nil
}

func actorFromSendSealingIntent(intent *generated.SendSealingIntent) Actor {
	a := Actor{Via: "worker"}
	if intent == nil {
		return a
	}
	a.OrgID, a.Email, a.IP, a.Via, a.Tool = intent.OrgID, intent.ActorEmail, intent.ActorIp, intent.Via, intent.Tool
	if a.Via == "" {
		a.Via = "worker"
	}
	if intent.ActorUserID.Valid {
		id := uuid.UUID(intent.ActorUserID.Bytes)
		a.UserID = &id
	}
	return a
}

func verifyPreparedSealedDocument(prepared, locked *generated.Document) error {
	if prepared == nil || locked == nil {
		return ErrDraftChangedDuringSend
	}
	before, after := *prepared, *locked
	before.Status, after.Status = "sealing", "sealing"
	return verifyPreparedSendDocument(&before, &after)
}

func truncateString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func retainSendEvidence(ctx context.Context, retainer EvidenceRetainer, doc *generated.Document, retainUntil time.Time) error {
	if doc == nil {
		return ErrDocumentNotFound
	}
	if doc.SourceKind != "pdf" && doc.RequiresSignature {
		return nil
	}
	type artifact struct {
		key, versionID string
		digest         []byte
	}
	artifacts := make([]artifact, 0, 2)
	if doc.PdfStorageKey.Valid && doc.PdfStorageKey.String != "" {
		artifacts = append(artifacts, artifact{doc.PdfStorageKey.String, doc.PdfStorageVersionID.String, doc.PdfSha256})
	}
	if doc.RenderedPdfKey.Valid && doc.RenderedPdfKey.String != "" &&
		(!doc.PdfStorageKey.Valid || doc.RenderedPdfKey.String != doc.PdfStorageKey.String) {
		artifacts = append(artifacts, artifact{doc.RenderedPdfKey.String, doc.RenderedPdfVersionID.String, doc.RenderedPdfSha})
	}
	if len(artifacts) == 0 {
		return nil
	}
	if retainer == nil {
		return errors.New("send document: evidence retention unavailable")
	}
	for _, artifact := range artifacts {
		if strings.TrimSpace(artifact.key) == "" || strings.TrimSpace(artifact.versionID) == "" || len(artifact.digest) != sha256.Size {
			return fmt.Errorf("retain send evidence %q: committed SHA-256 or VersionId is unavailable", artifact.key)
		}
		if err := retainer.RetainEvidenceVersion(ctx, artifact.key, artifact.versionID, artifact.digest, retainUntil); err != nil {
			return fmt.Errorf("retain send evidence %q: %w", artifact.key, err)
		}
	}
	return nil
}

func retainReadySendEvidence(ctx context.Context, retainer EvidenceRetainer, doc *generated.Document, recipients []*generated.Recipient, fields []*generated.DocumentField, pageCount int, retainUntil time.Time) error {
	if err := validateAcknowledgementSend(doc); err != nil {
		return err
	}
	if doc != nil && doc.SourceKind == "pdf" && doc.RequiresSignature {
		if err := validatePDFSignatureFields(doc, recipients, fields, pageCount); err != nil {
			return err
		}
	}
	if doc != nil && doc.SourceKind == "pdf" && !doc.RequiresSignature {
		if err := validateAcknowledgementFields(fields); err != nil {
			return err
		}
	}
	return retainSendEvidence(ctx, retainer, doc, retainUntil)
}

func validateAcknowledgementFields(fields []*generated.DocumentField) error {
	if len(fields) != 0 {
		return fmt.Errorf("%w: found %d field(s)", ErrAcknowledgementFields, len(fields))
	}
	return nil
}

// inspectSendSourcePDF binds PDF-field readiness to the actual retained source
// bytes. A field on page 2 of a one-page contract must fail before any token or
// status mutation; otherwise pdfcpu would have nothing on which to stamp it.
// The digest check also prevents Send from authorizing a storage object that
// no longer matches the intake hash recorded on the document row.
func inspectSendSourcePDF(ctx context.Context, store EvidenceRetainer, doc *generated.Document) (int, error) {
	if doc == nil {
		return 0, ErrDocumentNotFound
	}
	if doc.SourceKind != "pdf" {
		return 0, nil
	}
	if !doc.PdfStorageKey.Valid || strings.TrimSpace(doc.PdfStorageKey.String) == "" || len(doc.PdfSha256) != sha256.Size {
		return 0, ErrAcknowledgementNeedsPDF
	}
	reader, ok := store.(sourceEvidenceReader)
	if !ok || reader == nil {
		return 0, errors.New("send PDF: evidence reader unavailable")
	}
	body, err := readSendEvidence(ctx, reader, doc.PdfStorageKey.String, doc.PdfStorageVersionID, doc.PdfSha256, doc.EvidenceVersionPinsRequired)
	if err != nil {
		return 0, fmt.Errorf("send PDF: load retained source: %w", err)
	}
	sum := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(sum[:], doc.PdfSha256) != 1 {
		return 0, errors.New("send PDF: source digest does not match recorded intake hash")
	}
	pageCount, err := sanitize.PageCount(body)
	if err != nil || pageCount < 1 {
		if err == nil {
			err = errors.New("PDF has no pages")
		}
		return 0, fmt.Errorf("send PDF: inspect retained source: %w", err)
	}
	return pageCount, nil
}

func readSendEvidence(ctx context.Context, reader sourceEvidenceReader, key string, versionID pgtype.Text, digest []byte, pinsRequired bool) ([]byte, error) {
	if reader == nil || strings.TrimSpace(key) == "" || len(digest) != sha256.Size {
		return nil, errors.New("send evidence commitment is incomplete")
	}
	if versionID.Valid && strings.TrimSpace(versionID.String) != "" {
		return reader.GetVerifiedVersion(ctx, key, versionID.String, digest)
	}
	if pinsRequired {
		return nil, errors.New("send evidence VersionId is required")
	}
	body, _, err := reader.ResolveVerifiedLegacy(ctx, key, digest)
	return body, err
}

// pinSendEvidenceVersions upgrades an explicitly legacy sealing row before
// retention starts. The source/rendered versions are resolved once by digest,
// written atomically to the document, and all later retries are exact-only.
func (e *Engine) pinSendEvidenceVersions(ctx context.Context, doc *generated.Document) (*generated.Document, error) {
	if e == nil || e.Queries == nil || doc == nil || doc.Status != "sealing" {
		return nil, errors.New("resume send sealing: document is unavailable for VersionId pinning")
	}
	reader, ok := e.Storage.(sourceEvidenceReader)
	if !ok || reader == nil {
		if !doc.PdfStorageKey.Valid && !doc.RenderedPdfKey.Valid {
			return e.Queries.PinDocumentSendEvidenceVersions(ctx, generated.PinDocumentSendEvidenceVersionsParams{
				ID: doc.ID, OrgID: doc.OrgID,
			})
		}
		return nil, errors.New("resume send sealing: evidence version resolver unavailable")
	}

	resolve := func(key pgtype.Text, digest []byte, current pgtype.Text) (pgtype.Text, error) {
		if !key.Valid || strings.TrimSpace(key.String) == "" {
			return pgtype.Text{}, nil
		}
		if len(digest) != sha256.Size {
			return pgtype.Text{}, fmt.Errorf("evidence %q has no valid SHA-256", key.String)
		}
		if current.Valid && strings.TrimSpace(current.String) != "" {
			if _, err := reader.GetVerifiedVersion(ctx, key.String, current.String, digest); err != nil {
				return pgtype.Text{}, err
			}
			return current, nil
		}
		if doc.EvidenceVersionPinsRequired {
			return pgtype.Text{}, fmt.Errorf("evidence %q is missing its required VersionId", key.String)
		}
		_, stored, err := reader.ResolveVerifiedLegacy(ctx, key.String, digest)
		if err != nil {
			return pgtype.Text{}, err
		}
		if strings.TrimSpace(stored.VersionID) == "" {
			return pgtype.Text{}, fmt.Errorf("evidence %q resolved without a VersionId", key.String)
		}
		return pgtype.Text{String: stored.VersionID, Valid: true}, nil
	}
	pdfVersion, err := resolve(doc.PdfStorageKey, doc.PdfSha256, doc.PdfStorageVersionID)
	if err != nil {
		return nil, fmt.Errorf("resume send sealing: pin source PDF VersionId: %w", err)
	}
	renderedVersion, err := resolve(doc.RenderedPdfKey, doc.RenderedPdfSha, doc.RenderedPdfVersionID)
	if err != nil {
		return nil, fmt.Errorf("resume send sealing: pin rendered PDF VersionId: %w", err)
	}
	pinned, err := e.Queries.PinDocumentSendEvidenceVersions(ctx, generated.PinDocumentSendEvidenceVersionsParams{
		PdfStorageVersionID: pdfVersion, RenderedPdfVersionID: renderedVersion,
		ID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil {
		return nil, fmt.Errorf("resume send sealing: persist evidence VersionIds: %w", err)
	}
	if pinned == nil || !pinned.EvidenceVersionPinsRequired ||
		(pinned.PdfStorageKey.Valid && !pinned.PdfStorageVersionID.Valid) ||
		(pinned.RenderedPdfKey.Valid && !pinned.RenderedPdfVersionID.Valid) {
		return nil, errors.New("resume send sealing: persisted evidence VersionIds are incomplete")
	}
	return pinned, nil
}

// validateAcknowledgementSend prevents the acknowledgement terminal path from
// promoting a NULL/non-PDF source into final_pdf_key. Acknowledgement evidence
// is deliberately limited to an original, intake-hashed PDF; block documents
// and envelope children need a real signature ceremony instead.
func validateAcknowledgementSend(doc *generated.Document) error {
	if doc == nil {
		return ErrDocumentNotFound
	}
	if doc.RequiresSignature {
		return nil
	}
	if doc.IsEnvelope {
		return ErrEnvelopeRequiresSignature
	}
	if doc.ParentEnvelopeID.Valid || doc.SourceKind != "pdf" ||
		!doc.PdfStorageKey.Valid || strings.TrimSpace(doc.PdfStorageKey.String) == "" ||
		len(doc.PdfSha256) != 32 {
		return ErrAcknowledgementNeedsPDF
	}
	return nil
}

type documentBlocksUpdater interface {
	UpdateDocumentBlocks(context.Context, generated.UpdateDocumentBlocksParams) (*generated.Document, error)
}

type documentFreezer interface {
	FreezeForSend(context.Context, *generated.Document) (json.RawMessage, []resolver.ResolveReport, error)
}

func freezeEnvelopeChildren(ctx context.Context, freezer documentFreezer, q documentBlocksUpdater, children []*generated.Document) ([]*generated.Document, error) {
	if freezer == nil {
		return nil, errors.New("send envelope: variable resolver unavailable")
	}
	updatedChildren := make([]*generated.Document, len(children))
	for i, child := range children {
		if child == nil {
			return nil, errors.New("send envelope: cannot freeze nil child")
		}
		frozen, _, err := freezer.FreezeForSend(ctx, child)
		if err != nil {
			return nil, fmt.Errorf("freeze envelope child %s: %w", child.ID, err)
		}
		candidate := *child
		candidate.VariablesJson = frozen
		if err := validateResolvedBlockVariables(&candidate); err != nil {
			return nil, fmt.Errorf("freeze envelope child %s: %w", child.ID, err)
		}
		updated, err := persistFrozenDocument(ctx, q, child, frozen)
		if err != nil {
			return nil, fmt.Errorf("persist frozen envelope child %s: %w", child.ID, err)
		}
		updatedChildren[i] = updated
	}
	return updatedChildren, nil
}

func persistFrozenDocument(ctx context.Context, q documentBlocksUpdater, doc *generated.Document, frozen json.RawMessage) (*generated.Document, error) {
	if q == nil {
		return nil, errors.New("document block store unavailable")
	}
	if doc == nil {
		return nil, errors.New("cannot freeze nil document")
	}
	updated, err := q.UpdateDocumentBlocks(ctx, generated.UpdateDocumentBlocksParams{
		ID:            doc.ID,
		OrgID:         doc.OrgID,
		BlocksJson:    doc.BlocksJson,
		VariablesJson: frozen,
	})
	if err != nil {
		return nil, err
	}
	if updated == nil {
		return nil, errors.New("document block update returned no document")
	}
	return updated, nil
}

// validateEnvelopeChildren verifies the complete pre-send shape and returns
// the sorted union of roles referenced by signature fields across all child
// trees. The envelope wrapper's own block tree is intentionally ignored.
func validateEnvelopeChildren(envelopeID uuid.UUID, children []*generated.Document) ([]string, error) {
	return validateEnvelopeChildrenForStatus(envelopeID, children, "draft")
}

func validateEnvelopeChildrenForStatus(envelopeID uuid.UUID, children []*generated.Document, requiredStatus string) ([]string, error) {
	return validateEnvelopeChildrenForStatusMode(envelopeID, children, requiredStatus, true)
}

func validateEnvelopeChildrenStructure(envelopeID uuid.UUID, children []*generated.Document, requiredStatus string) error {
	_, err := validateEnvelopeChildrenForStatusMode(envelopeID, children, requiredStatus, false)
	return err
}

func validateEnvelopeChildrenForStatusMode(envelopeID uuid.UUID, children []*generated.Document, requiredStatus string, projectRoles bool) ([]string, error) {
	if len(children) == 0 {
		return nil, errors.New("send envelope: envelope has no children")
	}
	roleSet := make(map[string]struct{})
	for i, child := range children {
		if child == nil {
			return nil, fmt.Errorf("send envelope: child %d is nil", i+1)
		}
		if !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != envelopeID {
			return nil, fmt.Errorf("send envelope: child %s is no longer attached", child.ID)
		}
		if child.IsEnvelope {
			return nil, fmt.Errorf("send envelope: child %s is itself an envelope", child.ID)
		}
		if child.Status != requiredStatus {
			return nil, fmt.Errorf("send envelope: child %s is not %s", child.ID, requiredStatus)
		}
		if child.SourceKind != "blocks" {
			return nil, fmt.Errorf("send envelope: child %s must be blocks-source", child.ID)
		}
		tree, err := blocks.ParseCanonicalTree(child.BlocksJson)
		if err != nil {
			return nil, fmt.Errorf("send envelope: parse child %s blocks: %w", child.ID, err)
		}
		if err := validateImmutableBlockEvidence(tree); err != nil {
			return nil, fmt.Errorf("send envelope: child %s: %w", child.ID, err)
		}
		if projectRoles {
			values, err := blocks.ParseVariableValues(child.VariablesJson)
			if err != nil {
				return nil, fmt.Errorf("send envelope: child %s variables: %w", child.ID, err)
			}
			roles, err := blocks.RequiredSignerRolesForVariables(tree, values)
			if err != nil {
				return nil, fmt.Errorf("send envelope: child %s signer roles: %w", child.ID, err)
			}
			for _, role := range roles {
				roleSet[role] = struct{}{}
			}
		}
	}
	roles := make([]string, 0, len(roleSet))
	for role := range roleSet {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles, nil
}

func validateSendRecipients(doc *generated.Document, envelopeRoles []string, recs []*generated.Recipient) error {
	if doc == nil {
		return ErrDocumentNotFound
	}
	for _, rec := range recs {
		if rec == nil {
			return fmt.Errorf("%w: missing recipient row", ErrInvalidRecipient)
		}
		if err := recipients.ValidatePersisted(recipients.Values{
			Email: rec.Email, Name: rec.Name, Role: rec.Role,
			OrderIndex: rec.OrderIndex, Locale: rec.Locale,
		}); err != nil {
			return fmt.Errorf("%w: recipient %s: %v", ErrInvalidRecipient, rec.ID, err)
		}
		if rec.Role == "cc" || rec.Role == "viewer" {
			return fmt.Errorf("%w: recipient %s uses role %s", ErrUnsupportedRecipientRole, rec.ID, rec.Role)
		}
	}
	var requiredRoles []string
	if doc.IsEnvelope {
		requiredRoles = envelopeRoles
	} else if doc.SourceKind == "blocks" {
		tree, err := blocks.ParseCanonicalTree(doc.BlocksJson)
		if err != nil {
			return fmt.Errorf("send document: parse blocks: %w", err)
		}
		if err := validateImmutableBlockEvidence(tree); err != nil {
			return fmt.Errorf("send document: %w", err)
		}
		values, err := blocks.ParseVariableValues(doc.VariablesJson)
		if err != nil {
			return fmt.Errorf("send document: variables: %w", err)
		}
		requiredRoles, err = blocks.RequiredSignerRolesForVariables(tree, values)
		if err != nil {
			return fmt.Errorf("send document: signer roles: %w", err)
		}
	} else if doc.RequiresSignature {
		// PDF field assignment is not represented in BlocksJson. Its legacy
		// signing ceremony has one canonical signing role.
		requiredRoles = []string{"signer"}
	}

	if !doc.RequiresSignature {
		eligible := 0
		for _, rec := range recs {
			if recipientEligibleForSend(rec) {
				eligible++
			}
		}
		if eligible == 0 {
			return ErrNoRecipients
		}
		return nil
	}
	if len(requiredRoles) == 0 {
		return ErrNoSignatureFields
	}
	eligible := 0
	for _, rec := range recs {
		if recipientEligibleForSend(rec) && rec.Role != "cc" {
			eligible++
		}
	}
	if eligible == 0 {
		return ErrNoSigners
	}
	return validateRequiredRoles(requiredRoles, recs)
}

// ValidateAutomationBlockRequest runs the stable block/variable/recipient
// send checks before an automation endpoint persists its draft. Provider,
// storage, billing, and row-lock checks still run in Send; this preflight keeps
// malformed templates and role mappings from leaving permanent orphan drafts.
func ValidateAutomationBlockRequest(blockTree, variablesJSON []byte, values []recipients.Values) error {
	doc := &generated.Document{
		SourceKind:        "blocks",
		BlocksJson:        blockTree,
		VariablesJson:     variablesJSON,
		RequiresSignature: true,
	}
	if err := validateResolvedBlockVariables(doc); err != nil {
		return err
	}
	persisted := make([]*generated.Recipient, 0, len(values))
	for _, value := range values {
		persisted = append(persisted, &generated.Recipient{
			Role: value.Role, Email: value.Email, Name: value.Name,
			OrderIndex: value.OrderIndex, Locale: value.Locale, Status: "pending",
		})
	}
	return validateSendRecipients(doc, nil, persisted)
}

// validateImmutableBlockEvidence rejects advertised authoring blocks that are
// not yet bound into the signer view and terminal PDF. Image assets are not
// attached to the renderer, and non-signature block fields have no persisted
// block-ID/value mapping. Sending either would certify content that is missing
// or still a literal placeholder, so launch-safe behavior is fail closed.
func validateImmutableBlockEvidence(tree *blocks.Tree) error {
	if tree == nil {
		return fmt.Errorf("%w: nil block tree", ErrUnsupportedBlockEvidence)
	}
	if err := blocks.ValidateImmutableSigningEvidence(tree); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupportedBlockEvidence, err)
	}
	return nil
}

// validateResolvedBlockVariables prevents a document from becoming immutable
// while it still contains authoring tokens. A literal {{variable}} in a signed
// PDF is not merely cosmetic: it can leave party identity, dates, price, or
// other contract terms undefined. Validation happens against the frozen map
// before any send-sealing state or recipient credential is created.
func validateResolvedBlockVariables(doc *generated.Document) error {
	if doc == nil {
		return ErrDocumentNotFound
	}
	if doc.SourceKind != "blocks" {
		return nil
	}
	tree, err := blocks.ParseCanonicalTree(doc.BlocksJson)
	if err != nil {
		return fmt.Errorf("%w: invalid block tree", ErrUnresolvedVariables)
	}
	if withdrawnBuiltInLegalDraft(tree) {
		return ErrUnsafeBuiltInLegalDraft
	}
	if _, err := blocks.ValidateResolvedVariableValues(tree, doc.VariablesJson); err != nil {
		return fmt.Errorf("%w: %v", ErrUnresolvedVariables, err)
	}
	return nil
}

// withdrawnBuiltInLegalDraft prevents already-seeded copies of the original
// Swedish services starter from bypassing the production endpoint gate. That
// revision incorrectly called Atomicsite Apache-2.0 software and incorporated
// a nonexistent Bilaga A DPA. Exact distinctive fragments keep this migration
// guard narrow while making old templates/documents fail closed at every send
// surface, including worker recovery.
func withdrawnBuiltInLegalDraft(tree *blocks.Tree) bool {
	if tree == nil {
		return false
	}
	const (
		withdrawnLicenseClaim = "Atomicsite-binären levereras under sin öppna licens Apache 2.0"
		withdrawnDPAClaim     = "Ett personuppgiftsbiträdesavtal (Bilaga A) gäller från driftstart"
		unreviewedKitMarker   = "DRAFT KIT v1 (auto-seeded by Hash"
	)
	var found bool
	var walk func([]blocks.Block)
	walk = func(items []blocks.Block) {
		for i := range items {
			block := &items[i]
			if strings.Contains(block.Text, withdrawnLicenseClaim) ||
				strings.Contains(block.Text, withdrawnDPAClaim) ||
				strings.Contains(block.Text, unreviewedKitMarker) {
				found = true
				return
			}
			for _, row := range block.Rows {
				for _, cell := range row {
					if strings.Contains(cell, withdrawnLicenseClaim) ||
						strings.Contains(cell, withdrawnDPAClaim) ||
						strings.Contains(cell, unreviewedKitMarker) {
						found = true
						return
					}
				}
			}
			walk(block.Content)
			if found {
				return
			}
		}
	}
	walk(tree.Blocks)
	return found
}

func validateResolvedSealedSnapshot(doc *generated.Document, children []*generated.Document) error {
	if err := validateResolvedBlockVariables(doc); err != nil {
		return fmt.Errorf("resume send sealing: validate frozen variables: %w", err)
	}
	for _, child := range children {
		if err := validateResolvedBlockVariables(child); err != nil {
			return fmt.Errorf("resume send envelope: validate child frozen variables: %w", err)
		}
	}
	return nil
}

func recipientEligibleForSend(rec *generated.Recipient) bool {
	if rec == nil {
		return false
	}
	// Production draft recipients are pending. The empty value keeps pure
	// construction tests and legacy pre-default rows compatible while terminal
	// or already-invited states cannot count toward a new ceremony.
	return rec.Status == "" || rec.Status == "pending"
}

func validateRequiredRoles(roles []string, recs []*generated.Recipient) error {
	counts := make(map[string]int, len(recs))
	required := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		required[role] = struct{}{}
	}
	for _, rec := range recs {
		if recipientEligibleForSend(rec) {
			if _, ok := required[rec.Role]; !ok {
				return fmt.Errorf("%w: recipient role %s has no required signature field", ErrUnsupportedRecipientRole, rec.Role)
			}
			counts[rec.Role]++
		}
	}
	want := append([]string(nil), roles...)
	sort.Strings(want)
	for _, role := range want {
		switch counts[role] {
		case 0:
			return fmt.Errorf("%w: %s", ErrMissingSignerForRole, role)
		case 1:
			// Exactly one recipient owns every field in this role.
		default:
			return fmt.Errorf("%w: %s (%d recipients)", ErrAmbiguousSignerForRole, role, counts[role])
		}
	}
	return nil
}

// validatePDFSignatureFields validates the PDF designer state while Send owns
// the document row lock. CreateDraftField takes the same lock, so this list is
// the stable legal snapshot that final stamping will consume.
func validatePDFSignatureFields(doc *generated.Document, recs []*generated.Recipient, fields []*generated.DocumentField, pageCount int) error {
	if doc == nil {
		return ErrDocumentNotFound
	}
	if doc.SourceKind != "pdf" || !doc.RequiresSignature {
		return nil
	}

	var signer *generated.Recipient
	for _, rec := range recs {
		if rec == nil || rec.Role != "signer" || !recipientEligibleForSend(rec) {
			continue
		}
		if signer != nil {
			return fmt.Errorf("%w: multiple eligible signer recipients", ErrInvalidPDFSignatureField)
		}
		signer = rec
	}
	if signer == nil {
		return fmt.Errorf("%w: no eligible signer recipient", ErrInvalidPDFSignatureField)
	}

	recipientsByID := make(map[uuid.UUID]*generated.Recipient, len(recs))
	for _, rec := range recs {
		if rec != nil {
			recipientsByID[rec.ID] = rec
		}
	}

	signatureFields := 0
	for i, field := range fields {
		if field == nil {
			return fmt.Errorf("%w: field %d is nil", ErrInvalidPDFSignatureField, i+1)
		}
		if field.DocumentID != doc.ID {
			return fmt.Errorf("%w: field %s belongs to another document", ErrInvalidPDFSignatureField, field.ID)
		}
		// Every designer field can become visible legal content. Validate its
		// page and geometry now, including optional non-signature fields, so a
		// later fill cannot strand finalization on an impossible stamp target.
		if !validPDFFieldPlacement(field, pageCount) {
			return fmt.Errorf("%w: field %s has invalid page geometry", ErrInvalidPDFSignatureField, field.ID)
		}
		// Every field that can be stamped into the final PDF belongs to the sole
		// required signer. Allowing an optional NULL/CC/approver-owned field would
		// let a non-signing recipient alter visible contract bytes while the signer
		// evidence is already captured and finalization is pending.
		if !field.RecipientID.Valid || uuid.UUID(field.RecipientID.Bytes) != signer.ID {
			return fmt.Errorf("%w: field %s is not owned by the sole signer", ErrInvalidPDFSignatureField, field.ID)
		}
		if field.Type != "signature" {
			continue
		}
		signatureFields++
		if !field.Required {
			return fmt.Errorf("%w: field %s is optional", ErrInvalidPDFSignatureField, field.ID)
		}
		if !field.RecipientID.Valid {
			return fmt.Errorf("%w: field %s has no recipient", ErrInvalidPDFSignatureField, field.ID)
		}
		ownerID := uuid.UUID(field.RecipientID.Bytes)
		owner, ok := recipientsByID[ownerID]
		if !ok || owner.Role != "signer" || owner.ID != signer.ID || !recipientEligibleForSend(owner) {
			role := "unknown"
			if ok {
				role = owner.Role
			}
			return fmt.Errorf("%w: field %s is assigned to %s recipient %s", ErrInvalidPDFSignatureField, field.ID, role, ownerID)
		}
	}
	if signatureFields == 0 {
		return fmt.Errorf("%w: no signature field", ErrInvalidPDFSignatureField)
	}
	return nil
}

func validPDFFieldPlacement(field *generated.DocumentField, pageCount int) bool {
	if field == nil || pageCount < 1 || field.Page < 1 || int(field.Page) > pageCount {
		return false
	}
	x, xok := finiteNumeric(field.XPct)
	y, yok := finiteNumeric(field.YPct)
	w, wok := finiteNumeric(field.WPct)
	h, hok := finiteNumeric(field.HPct)
	if !xok || !yok || !wok || !hok {
		return false
	}
	return x >= 0 && y >= 0 && w > 0 && h > 0 && x < 100 && y < 100 && x+w <= 100 && y+h <= 100
}

func finiteNumeric(value pgtype.Numeric) (float64, bool) {
	if !value.Valid || value.Int == nil || value.NaN || value.InfinityModifier != pgtype.Finite {
		return 0, false
	}
	converted, err := value.Float64Value()
	if err != nil || !converted.Valid || math.IsNaN(converted.Float64) || math.IsInf(converted.Float64, 0) {
		return 0, false
	}
	return converted.Float64, true
}

// verifyPreparedEnvelopeChildren catches membership or content changes that
// raced preflight/freeze before any recipient token is rotated. Both slices
// are position-ordered by ListEnvelopeChildren.
func verifyPreparedEnvelopeChildren(prepared, locked []*generated.Document) error {
	if len(prepared) != len(locked) {
		return errors.New("send envelope: child membership changed while preparing send")
	}
	for i := range prepared {
		before, after := prepared[i], locked[i]
		if before == nil || after == nil || before.ID != after.ID {
			return errors.New("send envelope: child membership changed while preparing send")
		}
		if before.Name != after.Name ||
			!bytes.Equal(before.BlocksJson, after.BlocksJson) ||
			!bytes.Equal(before.VariablesJson, after.VariablesJson) {
			return fmt.Errorf("send envelope: child %s changed while preparing send", before.ID)
		}
	}
	return nil
}

func verifyPreparedSendDocument(prepared, locked *generated.Document) error {
	if prepared == nil || locked == nil || prepared.ID != locked.ID || prepared.OrgID != locked.OrgID {
		return ErrDraftChangedDuringSend
	}
	if prepared.Name != locked.Name || prepared.Status != locked.Status ||
		prepared.SourceKind != locked.SourceKind || prepared.RoutingMode != locked.RoutingMode ||
		prepared.RoutingTier != locked.RoutingTier || prepared.RequiresSignature != locked.RequiresSignature ||
		prepared.IsEnvelope != locked.IsEnvelope || prepared.DefaultLocale != locked.DefaultLocale ||
		prepared.BilingualTargetLang != locked.BilingualTargetLang || prepared.LawfulBasis != locked.LawfulBasis ||
		prepared.NegotiationEnabled != locked.NegotiationEnabled ||
		prepared.RenderedPdfKey != locked.RenderedPdfKey || prepared.PdfStorageKey != locked.PdfStorageKey ||
		prepared.RenderedPdfVersionID != locked.RenderedPdfVersionID || prepared.PdfStorageVersionID != locked.PdfStorageVersionID ||
		prepared.EvidenceVersionPinsRequired != locked.EvidenceVersionPinsRequired ||
		prepared.ParentEnvelopeID != locked.ParentEnvelopeID || prepared.EnvelopePosition != locked.EnvelopePosition ||
		!bytes.Equal(prepared.BlocksJson, locked.BlocksJson) ||
		!bytes.Equal(prepared.VariablesJson, locked.VariablesJson) ||
		!bytes.Equal(prepared.Metadata, locked.Metadata) ||
		!bytes.Equal(prepared.RenderedPdfSha, locked.RenderedPdfSha) ||
		!bytes.Equal(prepared.PdfSha256, locked.PdfSha256) ||
		prepared.ExpiresAt.Valid != locked.ExpiresAt.Valid ||
		(prepared.ExpiresAt.Valid && !prepared.ExpiresAt.Time.Equal(locked.ExpiresAt.Time)) {
		return fmt.Errorf("%w: %s", ErrDraftChangedDuringSend, prepared.ID)
	}
	return nil
}

// ValidateLawfulBasis accepts only the Article 6 basis for which Hash currently
// implements a defensible ceremony. Other bases require basis-specific product
// evidence (for example consent withdrawal or a legitimate-interest balancing
// assessment) before Hash may represent them to a signer.
//
// It is exported so REST and MCP surfaces can reject bad input before invoking
// the lifecycle engine, while Send repeats the check as the final authority.
func ValidateLawfulBasis(value string) error {
	if _, err := article13.LegalBasisDisclosureV1(value); err == nil {
		return nil
	}
	return ErrLawfulBasisUnconfirmed
}

func requireConfirmedLawfulBasis(doc *generated.Document, confirmation *generated.DocumentLawfulBasisConfirmation) error {
	if doc == nil || confirmation == nil || !confirmation.ConfirmedAt.Valid ||
		confirmation.DocumentID != doc.ID || confirmation.OrgID != doc.OrgID ||
		strings.TrimSpace(confirmation.LawfulBasis) != strings.TrimSpace(doc.LawfulBasis) ||
		strings.TrimSpace(confirmation.ControllerName) == "" ||
		strings.TrimSpace(confirmation.ControllerContact) == "" {
		return ErrLawfulBasisUnconfirmed
	}
	return ValidateLawfulBasis(confirmation.LawfulBasis)
}

func requireValidSignerDisclosure(doc *generated.Document, confirmation *generated.DocumentLawfulBasisConfirmation) error {
	if doc == nil || confirmation == nil {
		return ErrInvalidSignerDisclosure
	}
	err := article13.ValidateDisclosurePreflight(article13.DisclosurePreflight{
		DocumentName:      doc.Name,
		Controller:        confirmation.ControllerName,
		ControllerContact: confirmation.ControllerContact,
		LawfulBasis:       confirmation.LawfulBasis,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignerDisclosure, err)
	}
	return nil
}

type documentStatusSetter interface {
	SetDocumentStatus(context.Context, generated.SetDocumentStatusParams) (*generated.Document, error)
}

// Void moves a sent/in-progress document to voided, cancels reminders, and
// invalidates every magic link so a still-live link can do nothing further.
func (e *Engine) Void(ctx context.Context, a Actor, docID uuid.UUID, reason string) error {
	if e.Pool == nil || e.Queries == nil || e.Audit == nil {
		return errors.New("void document: lifecycle store unavailable")
	}
	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin void: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)

	// Parent first is the shared lock order used by send, envelope topology
	// mutations, and finalize. It serializes membership and prevents a child
	// from being detached while the family is transitioned.
	doc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: docID, OrgID: a.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDocumentNotFound
	}
	if err != nil {
		return err
	}
	if err := requireLifecycleRoot(doc); err != nil {
		return err
	}
	if !voidableStatus(doc.Status) {
		return ErrNotVoidable
	}

	var children []*generated.Document
	if doc.IsEnvelope {
		listed, lerr := q.ListEnvelopeChildren(ctx, generated.ListEnvelopeChildrenParams{
			ParentEnvelopeID: pgtype.UUID{Bytes: doc.ID, Valid: true},
			OrgID:            doc.OrgID,
		})
		if lerr != nil {
			return fmt.Errorf("void envelope: list children: %w", lerr)
		}
		children = make([]*generated.Document, 0, len(listed))
		for _, listedChild := range listed {
			child, lerr := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{
				ID: listedChild.ID, OrgID: doc.OrgID,
			})
			if lerr != nil {
				return fmt.Errorf("void envelope: lock child %s: %w", listedChild.ID, lerr)
			}
			if !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != doc.ID || child.IsEnvelope {
				return fmt.Errorf("void envelope: child %s has invalid membership", child.ID)
			}
			children = append(children, child)
		}
	}

	voidedChildIDs, err := voidLockedDocumentFamily(ctx, q, doc, children)
	if err != nil {
		return err
	}

	// Token/reminder shutdown is part of the same atomic lifecycle change. Even
	// though envelope recipients normally belong to the wrapper, cleaning every
	// child closes legacy or malformed bundles without leaving a live link.
	artifactDocIDs := make([]uuid.UUID, 0, len(children)+1)
	artifactDocIDs = append(artifactDocIDs, doc.ID)
	for _, child := range children {
		artifactDocIDs = append(artifactDocIDs, child.ID)
	}
	for _, id := range artifactDocIDs {
		if err := q.CancelReminder(ctx, id); err != nil {
			return fmt.Errorf("void document %s: cancel reminder: %w", id, err)
		}
		if err := q.InvalidateRecipientTokens(ctx, id); err != nil {
			return fmt.Errorf("void document %s: invalidate recipient tokens: %w", id, err)
		}
	}
	auditEntries := make([]audit.Entry, 0, len(voidedChildIDs)+1)
	for i := range voidedChildIDs {
		auditEntries = append(auditEntries, e.auditEntry(a, &voidedChildIDs[i], nil, audit.KindDocumentVoided, map[string]any{
			"reason": reason, "envelope_id": doc.ID.String(), "propagated": true,
		}))
	}
	auditEntries = append(auditEntries, e.auditEntry(a, &doc.ID, nil, audit.KindDocumentVoided, map[string]any{"reason": reason}))
	pendingAudits, err := appendAuditEntriesTx(ctx, e.Audit, tx, auditEntries)
	if err != nil {
		return fmt.Errorf("audit void: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit void: %w", err)
	}
	for _, pending := range pendingAudits {
		e.Audit.Publish(pending)
	}
	return nil
}

type documentVoider interface {
	VoidDocumentIfActive(context.Context, generated.VoidDocumentIfActiveParams) (*generated.Document, error)
}

func requireLifecycleRoot(doc *generated.Document) error {
	if doc == nil {
		return ErrDocumentNotFound
	}
	if doc.ParentEnvelopeID.Valid {
		return ErrEnvelopeChildLifecycle
	}
	return nil
}

// voidLockedDocumentFamily transitions children first and the wrapper last.
// The caller holds row locks and a surrounding transaction, so any error from
// this helper rolls every earlier child update back. A completed child makes
// the entire envelope non-voidable: voiding only the wrapper would conceal an
// already-final legal artifact, while voiding that child would destroy it.
func voidLockedDocumentFamily(ctx context.Context, q documentVoider, parent *generated.Document, children []*generated.Document) ([]uuid.UUID, error) {
	if q == nil {
		return nil, errors.New("void document: lifecycle store unavailable")
	}
	if parent == nil {
		return nil, errors.New("void document: nil parent")
	}
	if !voidableStatus(parent.Status) {
		return nil, ErrNotVoidable
	}

	// Inspect the whole family before the first write. The surrounding
	// transaction is the atomicity boundary, and this preflight additionally
	// avoids doing work that is already known to be rolled back.
	for _, child := range children {
		if child == nil {
			return nil, errors.New("void envelope: nil child")
		}
		if !voidableStatus(child.Status) {
			return nil, fmt.Errorf("void envelope: child %s: %w", child.ID, ErrNotVoidable)
		}
	}

	voidedChildren := make([]uuid.UUID, 0, len(children))
	for _, child := range children {
		if err := voidLockedDocument(ctx, q, child); err != nil {
			return nil, fmt.Errorf("void envelope child %s: %w", child.ID, err)
		}
		voidedChildren = append(voidedChildren, child.ID)
	}
	if err := voidLockedDocument(ctx, q, parent); err != nil {
		return nil, fmt.Errorf("void document %s: %w", parent.ID, err)
	}
	return voidedChildren, nil
}

func voidLockedDocument(ctx context.Context, q documentVoider, doc *generated.Document) error {
	updated, err := q.VoidDocumentIfActive(ctx, generated.VoidDocumentIfActiveParams{
		ID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotVoidable
		}
		return err
	}
	if updated == nil || updated.ID != doc.ID || updated.Status != "voided" {
		return errors.New("void transition returned invalid state")
	}
	return nil
}

func voidableStatus(status string) bool {
	return status == "sent" || status == "in_progress"
}

// Expire performs the worker's due active->expired transition. Envelope
// wrappers are the sole lifecycle roots: an attached child candidate is
// skipped, while an expiring wrapper locks and expires every active child in
// the same transaction. The bool is false when the guarded parent transition
// lost a race or the candidate is an attached child.
func (e *Engine) Expire(ctx context.Context, candidate *generated.Document) (bool, error) {
	if candidate == nil {
		return false, errors.New("expire document: nil candidate")
	}
	if e.Pool == nil || e.Queries == nil || e.Audit == nil {
		return false, errors.New("expire document: lifecycle store unavailable")
	}
	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin expiration: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)

	parent, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{
		ID: candidate.ID, OrgID: candidate.OrgID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lock expiration candidate: %w", err)
	}
	// GetExpirableDocuments can discover a child whose own expires_at is set.
	// A child must never terminate independently from its shared ceremony; its
	// parent wrapper will propagate expiration when the envelope itself is due.
	if parent.ParentEnvelopeID.Valid {
		return false, nil
	}

	var children []*generated.Document
	if parent.IsEnvelope {
		listed, lerr := q.ListEnvelopeChildren(ctx, generated.ListEnvelopeChildrenParams{
			ParentEnvelopeID: pgtype.UUID{Bytes: parent.ID, Valid: true},
			OrgID:            parent.OrgID,
		})
		if lerr != nil {
			return false, fmt.Errorf("expire envelope: list children: %w", lerr)
		}
		children = make([]*generated.Document, 0, len(listed))
		for _, listedChild := range listed {
			child, lerr := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{
				ID: listedChild.ID, OrgID: parent.OrgID,
			})
			if lerr != nil {
				return false, fmt.Errorf("expire envelope: lock child %s: %w", listedChild.ID, lerr)
			}
			if !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != parent.ID || child.IsEnvelope {
				return false, fmt.Errorf("expire envelope: child %s has invalid membership", child.ID)
			}
			children = append(children, child)
		}
	}

	expiredParent, err := q.ExpireDocumentIfActive(ctx, generated.ExpireDocumentIfActiveParams{
		ID: parent.ID, OrgID: parent.OrgID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("expire document: %w", err)
	}
	if expiredParent == nil || expiredParent.ID != parent.ID || expiredParent.Status != "expired" {
		return false, errors.New("expire document: transition returned invalid state")
	}

	expiredChildIDs, err := expireLockedEnvelopeChildren(ctx, q, children)
	if err != nil {
		return false, err
	}
	artifactDocIDs := make([]uuid.UUID, 0, len(children)+1)
	artifactDocIDs = append(artifactDocIDs, parent.ID)
	for _, child := range children {
		artifactDocIDs = append(artifactDocIDs, child.ID)
	}
	for _, id := range artifactDocIDs {
		if err := q.InvalidateRecipientTokens(ctx, id); err != nil {
			return false, fmt.Errorf("expire document %s: invalidate recipient tokens: %w", id, err)
		}
		if err := q.CancelReminder(ctx, id); err != nil {
			return false, fmt.Errorf("expire document %s: cancel reminder: %w", id, err)
		}
	}

	pending := make([]audit.PendingEvent, 0, len(expiredChildIDs)+1)
	parentEvent, err := e.Audit.LogTx(ctx, tx, audit.Entry{
		OrgID: parent.OrgID, DocumentID: &parent.ID, Kind: audit.KindDocumentExpired,
	})
	if err != nil {
		return false, fmt.Errorf("audit expiration: %w", err)
	}
	pending = append(pending, parentEvent)
	for i := range expiredChildIDs {
		childID := expiredChildIDs[i]
		childEvent, err := e.Audit.LogTx(ctx, tx, audit.Entry{
			OrgID: parent.OrgID, DocumentID: &childID, Kind: audit.KindDocumentExpired,
			Payload: map[string]any{"envelope_id": parent.ID.String(), "propagated": true},
		})
		if err != nil {
			return false, fmt.Errorf("audit envelope child expiration: %w", err)
		}
		pending = append(pending, childEvent)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit expiration: %w", err)
	}
	for _, event := range pending {
		e.Audit.Publish(event)
	}
	return true, nil
}

func expireLockedEnvelopeChildren(ctx context.Context, q documentStatusSetter, children []*generated.Document) ([]uuid.UUID, error) {
	if q == nil {
		return nil, errors.New("expire envelope: document status store unavailable")
	}
	for _, child := range children {
		if child == nil {
			return nil, errors.New("expire envelope: nil child")
		}
		switch child.Status {
		case "sent", "in_progress", "expired":
			// Valid shared-ceremony states. Already-expired children are
			// idempotent and skipped in the mutation pass below.
		default:
			return nil, fmt.Errorf("expire envelope: child %s has incompatible status %s", child.ID, child.Status)
		}
	}
	expiredIDs := make([]uuid.UUID, 0, len(children))
	for _, child := range children {
		if child.Status == "expired" {
			continue
		}
		updated, err := q.SetDocumentStatus(ctx, generated.SetDocumentStatusParams{
			ID: child.ID, OrgID: child.OrgID, Status: "expired",
		})
		if err != nil {
			return nil, fmt.Errorf("expire envelope child %s: %w", child.ID, err)
		}
		if updated == nil || updated.ID != child.ID || updated.Status != "expired" {
			return nil, fmt.Errorf("expire envelope child %s: transition returned invalid state", child.ID)
		}
		expiredIDs = append(expiredIDs, child.ID)
	}
	return expiredIDs, nil
}

// Remind re-mints magic links (always with an expiry) and re-sends reminder
// emails to recipients still pending on a sent/in-progress document. The
// automatic flag distinguishes the worker's scheduled fire from a manual
// remind; the worker continues to own AdvanceReminder, so a manual remind also
// pushes the next scheduled fire out.
func (e *Engine) Remind(ctx context.Context, a Actor, docID uuid.UUID, automatic bool) (int, error) {
	if e.Pool == nil || e.Queries == nil || e.Audit == nil {
		return 0, errors.New("remind document: lifecycle store unavailable")
	}
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
	doc = lockedDoc
	recs, err := q.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil {
		return 0, fmt.Errorf("re-list reminder recipients: %w", err)
	}
	exp := magictoken.Expiry(doc.ExpiresAt, e.now())
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
		if err := q.ResetReminderAfterManualRemind(ctx, doc.ID); err != nil {
			return 0, fmt.Errorf("reset manual reminder schedule: %w", err)
		}
	}
	queueBacked := usesDurableEmailQueue(e.Mailer)
	if queueBacked {
		messages := make([]dispatch.Message, 0, len(reminders))
		for _, rm := range reminders {
			msg, rerr := e.renderEmail(dispatch.KindReminder, rm.email, rm.name, doc.Name, a.Email, rm.signURL, rm.beaconURL, rm.locale, doc.RequiresSignature)
			if rerr != nil {
				return 0, fmt.Errorf("render reminder email: %w", rerr)
			}
			messages = append(messages, msg)
		}
		if err := enqueueLifecycleEmails(ctx, q, messages); err != nil {
			return 0, fmt.Errorf("persist reminder outbox: %w", err)
		}
	}
	auditEntries := make([]audit.Entry, 0, len(reminders))
	for i := range reminders {
		rm := &reminders[i]
		payload := map[string]any{}
		if automatic {
			payload["automatic"] = true
		} else {
			payload["manual"] = true
		}
		auditEntries = append(auditEntries, e.auditEntry(a, &doc.ID, &rm.recID, audit.KindReminderSent, payload))
	}
	pendingAudits, err := appendAuditEntriesTx(ctx, e.Audit, tx, auditEntries)
	if err != nil {
		return 0, fmt.Errorf("audit reminder: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit remind: %w", err)
	}
	for _, pending := range pendingAudits {
		e.Audit.Publish(pending)
	}

	if !queueBacked {
		for _, rm := range reminders {
			e.sendEmail(dispatch.KindReminder, rm.email, rm.name, doc.Name, a.Email, rm.signURL, rm.beaconURL, rm.locale, doc.RequiresSignature)
		}
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

func (e *Engine) renderEmail(kind, toEmail, toName, docName, senderEmail, signURL, beaconURL, locale string, requiresSignature bool) (dispatch.Message, error) {
	subj, html, text, err := dispatch.Render(kind, dispatch.TemplateContext{
		DocumentName:    docName,
		SenderName:      senderEmail,
		SenderEmail:     senderEmail,
		RecipientName:   toName,
		OrgName:         e.OrgName,
		Locale:          locale,
		SignURL:         signURL,
		BeaconURL:       beaconURL,
		Acknowledgement: !requiresSignature,
	})
	if err != nil {
		return dispatch.Message{}, err
	}
	return dispatch.Message{
		To: toEmail, Subject: subj, HTML: html, Text: text,
		ReplyTo: senderEmail, FromName: e.OrgName,
	}, nil
}

func (e *Engine) sendEmail(kind, toEmail, toName, docName, senderEmail, signURL, beaconURL, locale string, requiresSignature bool) {
	if e.Mailer == nil {
		return
	}
	msg, err := e.renderEmail(kind, toEmail, toName, docName, senderEmail, signURL, beaconURL, locale, requiresSignature)
	if err != nil {
		slog.Warn("send: email template render failed", "kind", kind, "err", err)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := e.Mailer.Send(ctx, msg); err != nil {
			slog.Warn("send: email send failed", "to", dispatch.MaskEmail(toEmail), "kind", kind, "err", dispatch.ScrubEmails(err.Error()))
		}
	}()
}

func usesDurableEmailQueue(mailer dispatch.Mailer) bool {
	switch mailer.(type) {
	case dispatch.QueueingMailer, *dispatch.QueueingMailer:
		return true
	default:
		return false
	}
}

type emailDeliveryEnqueuer interface {
	EnqueueEmailDelivery(context.Context, generated.EnqueueEmailDeliveryParams) (*generated.EmailDelivery, error)
}

func enqueueLifecycleEmails(ctx context.Context, q emailDeliveryEnqueuer, messages []dispatch.Message) error {
	if q == nil {
		return errors.New("email outbox unavailable")
	}
	for _, msg := range messages {
		headers := json.RawMessage("{}")
		if len(msg.Headers) > 0 {
			encoded, err := json.Marshal(msg.Headers)
			if err != nil {
				return fmt.Errorf("encode email headers: %w", err)
			}
			headers = encoded
		}
		row, err := q.EnqueueEmailDelivery(ctx, generated.EnqueueEmailDeliveryParams{
			ToEmail: msg.To, Subject: msg.Subject, HtmlBody: msg.HTML, TextBody: msg.Text,
			ReplyTo: msg.ReplyTo, FromName: msg.FromName, HeadersJson: headers,
		})
		if err != nil {
			return fmt.Errorf("enqueue email to %s: %w", dispatch.MaskEmail(msg.To), err)
		}
		if row == nil {
			return fmt.Errorf("enqueue email to %s returned no delivery", dispatch.MaskEmail(msg.To))
		}
	}
	return nil
}

type auditTxAppender interface {
	LogTx(context.Context, pgx.Tx, audit.Entry) (audit.PendingEvent, error)
}

func appendAuditEntriesTx(ctx context.Context, logger auditTxAppender, tx pgx.Tx, entries []audit.Entry) ([]audit.PendingEvent, error) {
	if logger == nil {
		return nil, errors.New("audit logger unavailable")
	}
	pending := make([]audit.PendingEvent, 0, len(entries))
	for _, entry := range entries {
		event, err := logger.LogTx(ctx, tx, entry)
		if err != nil {
			return nil, err
		}
		pending = append(pending, event)
	}
	return pending, nil
}

// documentSentAuditEntry is the only production constructor for a current
// document.sent event. Its epoch comes from the row returned by the guarded
// sealing completion UPDATE, never from a request clock or a prepared draft.
func (e *Engine) documentSentAuditEntry(a Actor, document *generated.Document, payload map[string]any) (audit.Entry, error) {
	if document == nil || document.ID == uuid.Nil || document.OrgID == uuid.Nil ||
		document.OrgID != a.OrgID || document.Status != "sent" ||
		!document.SentAt.Valid || document.SentAt.Time.IsZero() ||
		!document.Article13NoticeEpochAt.Valid ||
		!document.Article13NoticeEpochAt.Time.Equal(document.SentAt.Time) ||
		!article13.IsSupportedSchema(document.Article13NoticeSchema) ||
		!document.Article13NoticeEpochV61Committed {
		return audit.Entry{}, errors.New("document.sent audit requires the authoritative completed send result")
	}
	sentAt, err := article13.CanonicalSentAt(document.SentAt.Time)
	if err != nil {
		return audit.Entry{}, fmt.Errorf("document.sent audit epoch: %w", err)
	}
	withEpoch := make(map[string]any, len(payload)+1)
	for key, value := range payload {
		withEpoch[key] = value
	}
	withEpoch[article13.AuditRequiredNoticeSchemaKey] = document.Article13NoticeSchema
	withEpoch[article13.AuditRequiredNoticeSentAtKey] = sentAt
	return e.auditEntry(a, &document.ID, nil, audit.KindDocumentSent, withEpoch), nil
}

func (e *Engine) auditEntry(a Actor, docID, recID *uuid.UUID, kind string, payload map[string]any) audit.Entry {
	cloned := make(map[string]any, len(payload)+3)
	for key, value := range payload {
		cloned[key] = value
	}
	// The generic constructor deliberately does not manufacture Article 13
	// marker fields. documentSentAuditEntry is the only path allowed to create a
	// document.sent entry, because it binds both fields to the completed database
	// row. A partial CurrentSchema default here would make rolling-schema sends
	// ambiguous and could poison an otherwise valid event history.
	if a.Via != "" {
		cloned["via"] = a.Via
	}
	if a.Tool != "" {
		cloned["tool"] = a.Tool
	}
	return audit.Entry{
		OrgID: a.OrgID, ActorUserID: a.UserID, DocumentID: docID, RecipientID: recID,
		Kind: kind, IP: a.IP, Payload: cloned,
	}
}

func (e *Engine) log(ctx context.Context, a Actor, docID, recID *uuid.UUID, kind string, payload map[string]any) error {
	_, err := e.Audit.Log(ctx, e.auditEntry(a, docID, recID, kind, payload))
	return err
}

type eidasEvaluator interface {
	Evaluate(context.Context, uuid.UUID, eidas.EvaluateInput) (eidas.Decision, error)
}

// guardEnvelopeEIDASSend evaluates the wrapper and every frozen child, then
// enforces the highest tier required anywhere in the bundle. Evaluating each
// child independently avoids both failure modes of merging variables: one
// child's amount must not overwrite another's, and an `all` predicate must not
// accidentally combine fields that occur in different legal documents.
func guardEnvelopeEIDASSend(ctx context.Context, evaluator eidasEvaluator, orgID uuid.UUID, currentTier eidas.Tier, family []*generated.Document) (eidas.Decision, error) {
	if evaluator == nil {
		return eidas.Decision{}, errors.New("eidas: evaluator unavailable")
	}
	if len(family) == 0 {
		return eidas.Decision{}, errors.New("eidas: envelope has no documents to evaluate")
	}
	decisions := make([]eidas.Decision, 0, len(family))
	for _, doc := range family {
		if doc == nil {
			return eidas.Decision{}, errors.New("eidas: envelope contains nil document")
		}
		input, err := BuildEIDASEvaluateInput(doc)
		if err != nil {
			return eidas.Decision{}, fmt.Errorf("build eIDAS evaluation input for document %s: %w", doc.ID, err)
		}
		decision, err := evaluator.Evaluate(ctx, orgID, input)
		if err != nil {
			return eidas.Decision{}, fmt.Errorf("evaluate eIDAS rules for document %s: %w", doc.ID, err)
		}
		decisions = append(decisions, decision)
	}
	aggregated, err := aggregateEIDASDecisions(decisions)
	if err != nil {
		return eidas.Decision{}, err
	}
	if err := enforceEIDASSendDecision(currentTier, aggregated); err != nil {
		return aggregated, err
	}
	return aggregated, nil
}

func enforceEIDASSendDecision(currentTier eidas.Tier, decision eidas.Decision) error {
	if err := requireSupportedSignatureTier(currentTier, decision.RequiredTier); err != nil {
		return err
	}
	if currentTier.Cmp(decision.RequiredTier) < 0 {
		return &eidas.GuardError{Decision: decision, CurrentTier: currentTier}
	}
	return nil
}

func requireSupportedSignatureTier(selected, required eidas.Tier) error {
	if selected != eidas.TierSES || required != eidas.TierSES {
		return fmt.Errorf("%w: selected=%s required=%s", ErrSignatureTierUnavailable, selected, required)
	}
	return nil
}

func aggregateEIDASDecisions(decisions []eidas.Decision) (eidas.Decision, error) {
	aggregated := eidas.Decision{RequiredTier: eidas.TierSES}
	seenRules := make(map[string]struct{})
	for _, decision := range decisions {
		if !decision.RequiredTier.Valid() {
			return eidas.Decision{}, fmt.Errorf("eidas: evaluator returned invalid required tier %q", decision.RequiredTier)
		}
		aggregated.EvaluatedCount += decision.EvaluatedCount
		if decision.RequiredTier.Cmp(aggregated.RequiredTier) > 0 {
			aggregated.RequiredTier = decision.RequiredTier
		}
		for _, rule := range decision.MatchedRules {
			key := rule.ID + "\x00" + rule.Name + "\x00" + string(rule.RequiredTier) + "\x00" + rule.Reason
			if _, ok := seenRules[key]; ok {
				continue
			}
			seenRules[key] = struct{}{}
			aggregated.MatchedRules = append(aggregated.MatchedRules, rule)
		}
	}
	sort.SliceStable(aggregated.MatchedRules, func(i, j int) bool {
		return aggregated.MatchedRules[i].RequiredTier.Cmp(aggregated.MatchedRules[j].RequiredTier) > 0
	})
	return aggregated, nil
}

// BuildEIDASEvaluateInput pulls the fields the eIDAS engine reasons over out of
// a document row (moved from the handler so REST + MCP share one builder).
func BuildEIDASEvaluateInput(doc *generated.Document) (eidas.EvaluateInput, error) {
	in := eidas.EvaluateInput{Variables: map[string]string{}}
	if len(doc.VariablesJson) == 0 {
		return in, nil
	}
	var raw map[string]any
	if err := json.Unmarshal(doc.VariablesJson, &raw); err != nil {
		return in, fmt.Errorf("decode document variables: %w", err)
	}
	for k, v := range raw {
		if s, ok := stringifyVarForEIDAS(v); ok {
			in.Variables[k] = s
		}
	}
	for _, key := range []string{"amount", "deal_amount", "total", "value"} {
		if v, ok := in.Variables[key]; ok {
			n, err := parseContractAmount(v)
			if err != nil {
				// A present but unreadable amount is not the same thing as an
				// absent amount. Silently treating it as zero weakens the eIDAS
				// tier exactly when the guard cannot understand its input.
				return in, fmt.Errorf("invalid %s: %w", key, err)
			}
			in.Amount = n
			// Keep custom predicates on variables.<amount-key> consistent with
			// the built-in amount field; both must see the normalized number.
			in.Variables[key] = strconv.FormatFloat(n, 'f', -1, 64)
			break
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
	return in, nil
}

// parseContractAmount accepts the human format used in our Swedish ceremony
// (Unicode thousands spaces and a decimal comma) while rejecting ambiguous or
// non-finite values. Invalid present amounts fail the send instead of silently
// downgrading the required signature tier to the zero-value SES floor.
func parseContractAmount(raw string) (float64, error) {
	value := strings.TrimSpace(raw)
	value = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, value)
	if value == "" {
		return 0, errors.New("amount is empty")
	}
	if strings.Count(value, ",") > 1 || (strings.Contains(value, ",") && strings.Contains(value, ".")) {
		return 0, errors.New("amount uses an ambiguous separator format")
	}
	if strings.Contains(value, ",") {
		value = strings.Replace(value, ",", ".", 1)
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, errors.New("amount must be a finite number")
	}
	return n, nil
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
