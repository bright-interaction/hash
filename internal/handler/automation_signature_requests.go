// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/magictoken"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/templatepin"
	"github.com/bright-interaction/hash/internal/versions"
)

const (
	automationIdempotencyHeader = "Idempotency-Key"
	automationMaxRecipients     = 50
	automationMaxVariables      = 256
	automationMaxNameBytes      = 1000
	automationMaxVariableBytes  = 64 * 1024
	automationMaxKeyBytes       = 200
	automationMinimumExpiryLead = send.MinimumExpiryLead
)

var (
	errAutomationIdempotencyConflict        = errors.New("automation idempotency key was already used with different content")
	errAutomationRequestGone                = errors.New("automation signature request document was deleted")
	errAutomationTemplateNotFound           = errors.New("automation signature request template not found")
	errAutomationTemplateInvalid            = errors.New("automation signature request template is invalid")
	errAutomationTemplatePreconditionFailed = errors.New("template version or content digest does not match")
	errAutomationCeremonySuperseded         = errors.New("automation signature request ceremony was revised and cannot be resent by replay")
	errAutomationExpiryTooSoon              = errors.New("expires_at must be at least 5 minutes in the future")
	automationRFC3339Pattern                = regexp.MustCompile(`^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$`)
	automationTemplateSHA256Pattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// automationTemplatePreconditionError retains which operator-owned pin
// drifted for internal tests/diagnostics while the HTTP boundary returns one
// stable, non-oracular 412 response.
type automationTemplatePreconditionError struct {
	ExpectedVersion       int32
	ActualVersion         int32
	ContentDigestMismatch bool
}

func (e *automationTemplatePreconditionError) Error() string {
	return errAutomationTemplatePreconditionFailed.Error()
}

func (e *automationTemplatePreconditionError) Unwrap() error {
	return errAutomationTemplatePreconditionFailed
}

type automationSignatureRequestInput struct {
	TemplateID            string                              `json:"template_id"`
	TemplateVersion       int32                               `json:"template_version"`
	TemplateContentSHA256 string                              `json:"template_content_sha256"`
	Name                  string                              `json:"name"`
	Variables             map[string]string                   `json:"variables"`
	Recipients            []automationSignatureRecipientInput `json:"recipients"`
	LawfulBasis           string                              `json:"lawful_basis"`
	ExpiresAt             string                              `json:"expires_at,omitempty"`
}

type automationSignatureRecipientInput struct {
	Role       string `json:"role,omitempty"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	OrderIndex int32  `json:"order_index,omitempty"`
	Locale     string `json:"locale,omitempty"`
}

// preparedAutomationSignatureRequest is the canonical, provider-neutral
// command whose JSON digest is bound to the caller's idempotency key. Defaults
// and normalizations happen before hashing so an omitted default and its
// explicit equivalent identify the same logical request.
type preparedAutomationSignatureRequest struct {
	TemplateID            uuid.UUID                              `json:"template_id"`
	TemplateVersion       int32                                  `json:"template_version"`
	TemplateContentSHA256 string                                 `json:"template_content_sha256"`
	Name                  string                                 `json:"name"`
	Variables             map[string]string                      `json:"variables"`
	Recipients            []preparedAutomationSignatureRecipient `json:"recipients"`
	LawfulBasis           string                                 `json:"lawful_basis"`
	ExpiresAt             string                                 `json:"expires_at,omitempty"`
}

type preparedAutomationSignatureRecipient struct {
	Role       string `json:"role"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	OrderIndex int32  `json:"order_index"`
	Locale     string `json:"locale"`
}

type automationSignatureRequestResponse struct {
	AutomationRequestID uuid.UUID `json:"automation_request_id"`
	DocumentID          uuid.UUID `json:"document_id"`
	Status              string    `json:"status"`
	Replayed            bool      `json:"replayed"`
}

type automationSignatureRequestProcessInput struct {
	User               auth.SessionUser
	Request            preparedAutomationSignatureRequest
	IdempotencyKeyHash [sha256.Size]byte
	RequestHash        [sha256.Size]byte
	IP                 string
	UserAgent          string
}

type automationSignatureRequestProcessor interface {
	processAutomationSignatureRequest(context.Context, automationSignatureRequestProcessInput) (automationSignatureRequestResponse, error)
}

// requireAutomationSignatureRequestScope is intentionally stricter than the
// generic MCP write gate: this one composite command both authors and sends.
// Document-agent credentials cannot create an unrelated org-level resource.
func requireAutomationSignatureRequestScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, scoped := auth.DocumentScopeFromContext(r.Context()); scoped {
			writeError(w, http.StatusForbidden, "document-scoped credentials cannot create signature requests")
			return
		}
		if !auth.HasScope(r.Context(), "write:authoring") || !auth.HasScope(r.Context(), "write:workflow") {
			writeError(w, http.StatusForbidden, "signature requests require write:authoring and write:workflow scopes")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// POST /api/automation/v1/signature-requests
func (s *Server) handleAutomationSignatureRequest(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if err := requireAutomationJSONContentType(r.Header.Values("Content-Type")); err != nil {
		writeError(w, http.StatusUnsupportedMediaType, err.Error())
		return
	}
	key, err := automationIdempotencyKey(r.Header.Values(automationIdempotencyHeader))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var in automationSignatureRequestInput
	if err := decodeAutomationSignatureRequestJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	prepared, requestHash, err := prepareAutomationSignatureRequest(in)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	processor := s.automationSignatureRequestProcessor()
	if processor == nil {
		writeError(w, http.StatusServiceUnavailable, "automation signature requests are unavailable")
		return
	}

	response, err := processor.processAutomationSignatureRequest(r.Context(), automationSignatureRequestProcessInput{
		User:               u,
		Request:            prepared,
		IdempotencyKeyHash: automationIdempotencyKeyHash(key),
		RequestHash:        requestHash,
		IP:                 clientIP(r),
		UserAgent:          r.UserAgent(),
	})
	if err != nil {
		switch {
		case errors.Is(err, errAutomationIdempotencyConflict):
			writeError(w, http.StatusConflict, errAutomationIdempotencyConflict.Error())
		case errors.Is(err, errAutomationCeremonySuperseded):
			writeError(w, http.StatusConflict, errAutomationCeremonySuperseded.Error())
		case errors.Is(err, errAutomationExpiryTooSoon):
			writeError(w, http.StatusBadRequest, errAutomationExpiryTooSoon.Error())
		case errors.Is(err, errAutomationRequestGone):
			writeError(w, http.StatusGone, "the idempotent signature request no longer has a document")
		case errors.Is(err, errAutomationTemplateNotFound):
			writeError(w, http.StatusNotFound, "template not found")
		case errors.Is(err, errAutomationTemplatePreconditionFailed):
			writeError(w, http.StatusPreconditionFailed, errAutomationTemplatePreconditionFailed.Error())
		case errors.Is(err, errAutomationTemplateInvalid):
			writeError(w, http.StatusUnprocessableEntity, "template cannot be used for an automation signature request")
		default:
			s.writeSendError(w, err)
		}
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	status := http.StatusCreated
	if response.Replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, response)
}

func requireAutomationJSONContentType(values []string) error {
	if len(values) != 1 {
		return errors.New("exactly one Content-Type: application/json header is required")
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return errors.New("Content-Type must be application/json")
	}
	if len(parameters) == 0 {
		return nil
	}
	charset, ok := parameters["charset"]
	if len(parameters) != 1 || !ok || !strings.EqualFold(charset, "utf-8") {
		return errors.New("Content-Type must use UTF-8 JSON")
	}
	return nil
}

func (s *Server) automationSignatureRequestProcessor() automationSignatureRequestProcessor {
	if s.automationSignatureRequestProcessorOverride != nil {
		return s.automationSignatureRequestProcessorOverride
	}
	if s.Pool == nil || s.Queries == nil || s.Audit == nil || s.Send == nil {
		return nil
	}
	return s
}

func (s *Server) automationBillingEngine() *billing.Engine {
	if s.Billing != nil {
		return s.Billing
	}
	if s.Send != nil {
		return s.Send.Billing
	}
	return nil
}

func (s *Server) processAutomationSignatureRequest(ctx context.Context, input automationSignatureRequestProcessInput) (automationSignatureRequestResponse, error) {
	request, replayed, err := s.materializeAutomationSignatureRequest(ctx, input)
	if err != nil {
		return automationSignatureRequestResponse{}, err
	}
	if !request.DocumentID.Valid {
		return automationSignatureRequestResponse{}, errAutomationRequestGone
	}
	documentID := uuid.UUID(request.DocumentID.Bytes)
	status, err := s.sendAutomationSignatureRequest(ctx, input.User, documentID, request.State, input.Request.LawfulBasis, input.IP)
	if err != nil {
		if errors.Is(err, send.ErrExpiryTooSoon) {
			return automationSignatureRequestResponse{}, errAutomationExpiryTooSoon
		}
		return automationSignatureRequestResponse{}, err
	}
	rows, err := s.Queries.MarkAutomationSignatureRequestSent(ctx, generated.MarkAutomationSignatureRequestSentParams{
		ID: request.ID, OrgID: input.User.OrgID, DocumentID: request.DocumentID,
	})
	if err != nil {
		return automationSignatureRequestResponse{}, fmt.Errorf("mark automation signature request sent: %w", err)
	}
	if rows != 1 {
		return automationSignatureRequestResponse{}, errors.New("mark automation signature request sent: durable request disappeared")
	}
	return automationSignatureRequestResponse{
		AutomationRequestID: request.ID,
		DocumentID:          documentID,
		Status:              status,
		Replayed:            replayed,
	}, nil
}

func (s *Server) materializeAutomationSignatureRequest(ctx context.Context, input automationSignatureRequestProcessInput) (*generated.AutomationSignatureRequest, bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("begin automation signature request: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := generated.New(tx)
	billingEngine := s.automationBillingEngine()
	if billingEngine != nil {
		if err := q.LockAutomationSignatureRequestQuota(ctx, input.User.OrgID.String()); err != nil {
			return nil, false, fmt.Errorf("lock automation signature request quota: %w", err)
		}
	}

	request, err := q.ClaimAutomationSignatureRequest(ctx, generated.ClaimAutomationSignatureRequestParams{
		OrgID: input.User.OrgID, IdempotencyKeyHash: input.IdempotencyKeyHash[:], RequestHash: input.RequestHash[:],
	})
	replayed := false
	if errors.Is(err, pgx.ErrNoRows) {
		replayed = true
		request, err = q.GetAutomationSignatureRequestForUpdate(ctx, generated.GetAutomationSignatureRequestForUpdateParams{
			OrgID: input.User.OrgID, IdempotencyKeyHash: input.IdempotencyKeyHash[:],
		})
		if err != nil {
			return nil, false, fmt.Errorf("load automation signature request replay: %w", err)
		}
		if len(request.RequestHash) != sha256.Size || subtle.ConstantTimeCompare(request.RequestHash, input.RequestHash[:]) != 1 {
			return nil, false, errAutomationIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, false, fmt.Errorf("commit automation signature request replay: %w", err)
		}
		return request, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("claim automation signature request: %w", err)
	}
	if err := validateFreshAutomationExpiry(input.Request.ExpiresAt, time.Now().UTC()); err != nil {
		return nil, false, err
	}

	template, err := q.GetTemplateForShare(ctx, generated.GetTemplateForShareParams{ID: input.Request.TemplateID, OrgID: input.User.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, errAutomationTemplateNotFound
	}
	if err != nil {
		return nil, false, fmt.Errorf("load automation signature request template: %w", err)
	}
	if template.SourceKind != "blocks" {
		return nil, false, fmt.Errorf("%w: template is not blocks-source", errAutomationTemplateInvalid)
	}
	templateContent, err := templatepin.Canonicalize(template.BlocksJson, template.VariablesJson)
	if err != nil {
		return nil, false, fmt.Errorf("%w: invalid canonical content: %v", errAutomationTemplateInvalid, err)
	}
	contentDigest := templateContent.SHA256Hex()
	if template.Version != input.Request.TemplateVersion || contentDigest != input.Request.TemplateContentSHA256 {
		return nil, false, &automationTemplatePreconditionError{
			ExpectedVersion:       input.Request.TemplateVersion,
			ActualVersion:         template.Version,
			ContentDigestMismatch: contentDigest != input.Request.TemplateContentSHA256,
		}
	}
	if s.automationTemplateSnapshotHook != nil {
		s.automationTemplateSnapshotHook()
	}
	blockTree := templateContent.BlocksJSON
	variables := templateContent.DefaultVariables
	for name, value := range input.Request.Variables {
		variables[name] = value
	}
	variablesJSON, err := json.Marshal(variables)
	if err != nil {
		return nil, false, fmt.Errorf("encode automation variables: %w", err)
	}
	preflightRecipients := make([]recipients.Values, 0, len(input.Request.Recipients))
	for _, recipient := range input.Request.Recipients {
		preflightRecipients = append(preflightRecipients, recipients.Values{
			Role: recipient.Role, Email: recipient.Email, Name: recipient.Name,
			OrderIndex: recipient.OrderIndex, Locale: recipient.Locale,
		})
	}
	if err := send.ValidateAutomationBlockRequest(blockTree, variablesJSON, preflightRecipients); err != nil {
		return nil, false, err
	}
	var expiresAt pgtype.Timestamptz
	if input.Request.ExpiresAt != "" {
		expires, parseErr := time.Parse(time.RFC3339Nano, input.Request.ExpiresAt)
		if parseErr != nil {
			return nil, false, errors.New("canonical automation expiry became invalid")
		}
		expiresAt = pgtype.Timestamptz{Time: expires, Valid: true}
	}
	document, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID:      input.User.OrgID,
		TemplateID: pgtype.UUID{Bytes: input.Request.TemplateID, Valid: true},
		Name:       input.Request.Name, BlocksJson: blockTree, VariablesJson: variablesJSON,
		SenderID: input.User.UserID, ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, false, fmt.Errorf("create automation signature document: %w", err)
	}

	pendingAudits := make([]audit.PendingEvent, 0, len(input.Request.Recipients)+1)
	pending, err := s.Audit.LogTx(ctx, tx, audit.Entry{
		OrgID: input.User.OrgID, ActorUserID: &input.User.UserID, DocumentID: &document.ID,
		Kind: audit.KindDocumentCreated, IP: input.IP, UserAgent: input.UserAgent,
		Payload: map[string]any{
			"name": document.Name, "source_kind": "blocks", "via": "automation",
			"automation_request_id": request.ID, "template_id": template.ID,
			"template_version": template.Version, "template_content_sha256": contentDigest,
		},
	})
	if err != nil {
		return nil, false, fmt.Errorf("audit automation signature document: %w", err)
	}
	pendingAudits = append(pendingAudits, pending)

	now := time.Now()
	for _, recipient := range input.Request.Recipients {
		_, tokenHash, err := auth.MintMagicToken()
		if err != nil {
			return nil, false, fmt.Errorf("mint automation recipient token: %w", err)
		}
		created, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{
			DocumentID: document.ID, Role: recipient.Role, Email: recipient.Email, Name: recipient.Name,
			OrderIndex: recipient.OrderIndex, Locale: recipient.Locale, MagicTokenHash: tokenHash,
			MagicTokenExpiresAt: magictoken.Expiry(document.ExpiresAt, now),
		})
		if err != nil {
			return nil, false, fmt.Errorf("create automation signature recipient: %w", err)
		}
		pending, err := s.Audit.LogTx(ctx, tx, audit.Entry{
			OrgID: input.User.OrgID, ActorUserID: &input.User.UserID, DocumentID: &document.ID, RecipientID: &created.ID,
			Kind: audit.KindRecipientCreated, IP: input.IP, UserAgent: input.UserAgent,
			Payload: map[string]any{
				"email": created.Email, "name": created.Name, "role": created.Role,
				"via": "automation", "automation_request_id": request.ID,
			},
		})
		if err != nil {
			return nil, false, fmt.Errorf("audit automation signature recipient: %w", err)
		}
		pendingAudits = append(pendingAudits, pending)
	}
	if billingEngine != nil {
		// The transaction sees its own new document and recipients. Enforcing
		// quota before commit makes a 402/entitlement outage roll back every PII,
		// audit, and idempotency write instead of stranding an unreported draft.
		transactionalBilling := billing.New(q, billingEngine.Provider, billingEngine.PublicURL, billingEngine.WebhookURL)
		if err := transactionalBilling.EnforceDocumentQuota(ctx, input.User.OrgID); err != nil {
			return nil, false, fmt.Errorf("enforce automation signature request quota: %w", err)
		}
	}
	if _, err := versions.New(q).Snapshot(ctx, versions.SnapshotInput{
		DocumentID: document.ID, OrgID: document.OrgID, Name: document.Name, SourceKind: document.SourceKind,
		BlocksJSON: document.BlocksJson, VariablesJS: document.VariablesJson, CreatedBy: &input.User.UserID,
		Via: versions.ViaAgent, Summary: "automation signature request",
	}); err != nil {
		return nil, false, fmt.Errorf("snapshot automation signature document: %w", err)
	}
	request, err = q.BindAutomationSignatureRequestDocument(ctx, generated.BindAutomationSignatureRequestDocumentParams{
		ID: request.ID, OrgID: input.User.OrgID, DocumentID: pgtype.UUID{Bytes: document.ID, Valid: true},
	})
	if err != nil {
		return nil, false, fmt.Errorf("bind automation signature document: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("commit automation signature request: %w", err)
	}
	for _, event := range pendingAudits {
		s.Audit.Publish(event)
	}
	return request, replayed, nil
}

func (s *Server) sendAutomationSignatureRequest(ctx context.Context, user auth.SessionUser, documentID uuid.UUID, requestState, lawfulBasis, ip string) (string, error) {
	document, err := s.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: documentID, OrgID: user.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errAutomationRequestGone
	}
	if err != nil {
		return "", fmt.Errorf("load automation signature document: %w", err)
	}
	if err := rejectSupersededAutomationCeremony(requestState, document); err != nil {
		return "", err
	}
	if automationRequestWasSent(document.Status) {
		return document.Status, nil
	}
	if document.Status == "draft" {
		// Replays can arrive long after materialization. Validate the persisted
		// absolute deadline again before Send; the engine repeats this under its
		// row lock before crossing into durable sealing.
		if err := send.ValidateExpiryForSend(document.ExpiresAt, time.Now().UTC()); err != nil {
			return "", err
		}
	}
	actor := send.Actor{
		UserID: &user.UserID, OrgID: user.OrgID, Email: user.Email, IP: ip,
		Via: "automation", Tool: "signature_request", LawfulBasis: lawfulBasis,
	}
	// Materialization already acquired the org quota lock and committed this
	// document as the command's durable reservation. Re-running the ordinary
	// Send billing check after that commit can strand the idempotency row and PII
	// draft when another surface creates a document or the plan changes between
	// phases. Keep every other Send dependency identical, but consume the
	// reservation instead of charging it a second time.
	automationSend := *s.Send
	automationSend.Billing = nil
	if document.Status == "sealing" {
		result, resumeErr := automationSend.ResumeSendSealing(ctx, document.ID, document.OrgID)
		if resumeErr == nil {
			return result.Status, nil
		}
		return s.reconcileAutomationSendError(ctx, &automationSend, documentID, resumeErr, actor)
	}
	if document.Status != "draft" {
		return "", send.ErrNotDraft
	}
	result, sendErr := automationSend.Send(ctx, actor, document.ID)
	if sendErr == nil {
		return result.Status, nil
	}
	return s.reconcileAutomationSendError(ctx, &automationSend, documentID, sendErr, actor)
}

// rejectSupersededAutomationCeremony prevents the original machine command
// from authorizing a second ceremony after a human change-request revision.
// article13_notice_epoch_at deliberately survives changes_requested -> draft,
// so it also closes the crash window where the first send committed but the
// automation request had not yet advanced from ready to sent.
func rejectSupersededAutomationCeremony(requestState string, document *generated.Document) error {
	if document == nil || document.Status != "draft" {
		return nil
	}
	if requestState == "sent" || document.Article13NoticeEpochAt.Valid {
		return errAutomationCeremonySuperseded
	}
	return nil
}

func validateFreshAutomationExpiry(value string, now time.Time) error {
	if value == "" {
		return nil
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return errors.New("canonical automation expiry became invalid")
	}
	if !expiresAt.After(now.Add(automationMinimumExpiryLead)) {
		return errAutomationExpiryTooSoon
	}
	return nil
}

func (s *Server) reconcileAutomationSendError(ctx context.Context, sendEngine *send.Engine, documentID uuid.UUID, original error, actor send.Actor) (string, error) {
	if sendEngine == nil {
		return "", errors.Join(original, errors.New("reconcile automation signature send: send engine unavailable"))
	}
	document, err := s.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: documentID, OrgID: actor.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errAutomationRequestGone
	}
	if err != nil {
		return "", errors.Join(original, fmt.Errorf("reconcile automation signature send: %w", err))
	}
	if automationRequestWasSent(document.Status) {
		return document.Status, nil
	}
	// A concurrent equivalent request can win Send's document lock and leave
	// this caller observing the durable sealing state. ResumeSendSealing is the
	// engine's documented idempotent recovery path; a second completion race is
	// reconciled by one final authoritative document read below.
	if errors.Is(original, send.ErrNotDraft) && document.Status == "sealing" {
		result, resumeErr := sendEngine.ResumeSendSealing(ctx, document.ID, document.OrgID)
		if resumeErr == nil {
			return result.Status, nil
		}
		latest, loadErr := s.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: documentID, OrgID: actor.OrgID})
		if loadErr == nil && automationRequestWasSent(latest.Status) {
			return latest.Status, nil
		}
		if loadErr != nil && !errors.Is(loadErr, pgx.ErrNoRows) {
			return "", errors.Join(resumeErr, loadErr)
		}
		return "", resumeErr
	}
	return "", original
}

func automationRequestWasSent(status string) bool {
	switch status {
	case "sent", "in_progress", "changes_requested", "finalizing", "completed", "declined", "voided", "expired":
		return true
	default:
		return false
	}
}

func decodeAutomationSignatureRequestJSON(w http.ResponseWriter, r *http.Request, target *automationSignatureRequestInput) error {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		return err
	}
	if !utf8.Valid(raw) {
		return errors.New("JSON must be valid UTF-8")
	}
	if err := validateUniqueJSONObject(raw); err != nil {
		return err
	}
	if err := validateExactJSONFieldNames(raw, target); err != nil {
		return err
	}
	if err := validateAutomationVariableJSONTypes(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

// encoding/json otherwise decodes an explicit JSON null into the empty string
// in map[string]string. Validate the original machine request bytes so null or
// any other JSON type can never become contractual text silently.
func validateAutomationVariableJSONTypes(raw []byte) error {
	var envelope struct {
		Variables json.RawMessage `json:"variables"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return errors.New("variables must be a JSON object of string values")
	}
	if len(envelope.Variables) == 0 {
		return nil
	}
	trimmed := bytes.TrimSpace(envelope.Variables)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("variables must be a JSON object of string values")
	}
	var variables map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &variables); err != nil || variables == nil {
		return errors.New("variables must be a JSON object of string values")
	}
	for _, encoded := range variables {
		value := bytes.TrimSpace(encoded)
		if len(value) == 0 || value[0] != '"' {
			return errors.New("variable values must be strings")
		}
		var decoded string
		if err := json.Unmarshal(value, &decoded); err != nil {
			return errors.New("variable values must be strings")
		}
	}
	return nil
}

func automationIdempotencyKey(values []string) (string, error) {
	if len(values) != 1 || values[0] == "" {
		return "", errors.New("exactly one Idempotency-Key header is required")
	}
	value := values[0]
	if value != strings.TrimSpace(value) {
		return "", errors.New("Idempotency-Key must not have surrounding whitespace")
	}
	if !utf8.ValidString(value) || len(value) > automationMaxKeyBytes {
		return "", fmt.Errorf("Idempotency-Key must be valid UTF-8 and at most %d bytes", automationMaxKeyBytes)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", errors.New("Idempotency-Key must not contain control characters")
		}
	}
	return value, nil
}

func automationIdempotencyKeyHash(value string) [sha256.Size]byte {
	return sha256.Sum256([]byte("hash:automation-signature-request:idempotency:v1\x00" + value))
}

func prepareAutomationSignatureRequest(in automationSignatureRequestInput) (preparedAutomationSignatureRequest, [sha256.Size]byte, error) {
	templateID, err := uuid.Parse(strings.TrimSpace(in.TemplateID))
	if err != nil || templateID == uuid.Nil {
		return preparedAutomationSignatureRequest{}, [sha256.Size]byte{}, errors.New("template_id must be a UUID")
	}
	if in.TemplateVersion <= 0 {
		return preparedAutomationSignatureRequest{}, [sha256.Size]byte{}, errors.New("template_version must be a positive integer")
	}
	if !automationTemplateSHA256Pattern.MatchString(in.TemplateContentSHA256) {
		return preparedAutomationSignatureRequest{}, [sha256.Size]byte{}, errors.New("template_content_sha256 must be exactly 64 lowercase hexadecimal characters")
	}
	name := strings.TrimSpace(in.Name)
	if !validAutomationPlainText(name, automationMaxNameBytes) {
		return preparedAutomationSignatureRequest{}, [sha256.Size]byte{}, fmt.Errorf("name must be plain text between 1 and %d bytes", automationMaxNameBytes)
	}
	lawfulBasis := strings.TrimSpace(in.LawfulBasis)
	if err := send.ValidateLawfulBasis(lawfulBasis); err != nil {
		return preparedAutomationSignatureRequest{}, [sha256.Size]byte{}, err
	}
	variables := in.Variables
	if variables == nil {
		variables = map[string]string{}
	}
	if len(variables) > automationMaxVariables {
		return preparedAutomationSignatureRequest{}, [sha256.Size]byte{}, fmt.Errorf("variables must contain at most %d entries", automationMaxVariables)
	}
	variablesJSON, err := json.Marshal(variables)
	if err != nil {
		return preparedAutomationSignatureRequest{}, [sha256.Size]byte{}, errors.New("variables could not be encoded")
	}
	if _, err := blocks.ParseVariableValues(variablesJSON); err != nil {
		return preparedAutomationSignatureRequest{}, [sha256.Size]byte{}, err
	}
	variablesCopy := make(map[string]string, len(variables))
	for key, value := range variables {
		if len(value) > automationMaxVariableBytes {
			return preparedAutomationSignatureRequest{}, [sha256.Size]byte{}, fmt.Errorf("variable %q exceeds %d bytes", key, automationMaxVariableBytes)
		}
		variablesCopy[key] = value
	}
	if len(in.Recipients) == 0 || len(in.Recipients) > automationMaxRecipients {
		return preparedAutomationSignatureRequest{}, [sha256.Size]byte{}, fmt.Errorf("recipients must contain between 1 and %d entries", automationMaxRecipients)
	}
	preparedRecipients := make([]preparedAutomationSignatureRecipient, 0, len(in.Recipients))
	seenRecipients := make(map[string]struct{}, len(in.Recipients))
	for _, recipient := range in.Recipients {
		role := recipient.Role
		if strings.TrimSpace(role) == "" {
			role = "signer"
		}
		locale := recipient.Locale
		if strings.TrimSpace(locale) == "" {
			locale = "en"
		}
		values, err := recipients.Normalize(recipients.Values{
			Email: recipient.Email, Name: recipient.Name, Role: role,
			OrderIndex: recipient.OrderIndex, Locale: locale,
		})
		if err != nil {
			return preparedAutomationSignatureRequest{}, [sha256.Size]byte{}, err
		}
		if err := recipients.ValidateResponseRole(values.Role); err != nil {
			return preparedAutomationSignatureRequest{}, [sha256.Size]byte{}, err
		}
		identity := values.Role + "\x00" + strings.ToLower(values.Email)
		if _, duplicate := seenRecipients[identity]; duplicate {
			return preparedAutomationSignatureRequest{}, [sha256.Size]byte{}, errors.New("recipients must not repeat the same role and email")
		}
		seenRecipients[identity] = struct{}{}
		preparedRecipients = append(preparedRecipients, preparedAutomationSignatureRecipient{
			Role: values.Role, Email: values.Email, Name: values.Name,
			OrderIndex: values.OrderIndex, Locale: values.Locale,
		})
	}
	expiresAt := ""
	if in.ExpiresAt != "" {
		if in.ExpiresAt != strings.TrimSpace(in.ExpiresAt) || !automationRFC3339Pattern.MatchString(in.ExpiresAt) {
			return preparedAutomationSignatureRequest{}, [sha256.Size]byte{}, errors.New("expires_at must be strict RFC3339 with at most 9 fractional digits")
		}
		expires, err := time.Parse(time.RFC3339Nano, in.ExpiresAt)
		if err != nil {
			return preparedAutomationSignatureRequest{}, [sha256.Size]byte{}, errors.New("expires_at must be strict RFC3339 with at most 9 fractional digits")
		}
		expiresAt = expires.UTC().Format(time.RFC3339Nano)
	}
	prepared := preparedAutomationSignatureRequest{
		TemplateID: templateID, TemplateVersion: in.TemplateVersion,
		TemplateContentSHA256: in.TemplateContentSHA256,
		Name:                  name, Variables: variablesCopy, Recipients: preparedRecipients,
		LawfulBasis: lawfulBasis, ExpiresAt: expiresAt,
	}
	canonical, err := json.Marshal(prepared)
	if err != nil {
		return preparedAutomationSignatureRequest{}, [sha256.Size]byte{}, errors.New("signature request could not be canonicalized")
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("hash:automation-signature-request:payload:v2\x00"))
	_, _ = hasher.Write(canonical)
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return prepared, digest, nil
}

func validAutomationPlainText(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) || value != strings.TrimSpace(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
