// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	blockschema "github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/sign"
)

// documentResponse is the JSON shape we return.
type documentResponse struct {
	ID                uuid.UUID       `json:"id"`
	OrgID             uuid.UUID       `json:"org_id"`
	TemplateID        string          `json:"template_id,omitempty"`
	Name              string          `json:"name"`
	Status            string          `json:"status"`
	RoutingMode       string          `json:"routing_mode"`
	SourceKind        string          `json:"source_kind"`
	RequiresSignature bool            `json:"requires_signature"`
	BlocksJSON        json.RawMessage `json:"blocks_json,omitempty"`
	VariablesJSON     json.RawMessage `json:"variables_json"`
	PDFStorageKey     string          `json:"pdf_storage_key,omitempty"`
	PDFSHA256         string          `json:"pdf_sha256,omitempty"`
	FinalPDFKey       string          `json:"final_pdf_key,omitempty"`
	AuditCertKey      string          `json:"audit_cert_key,omitempty"`
	ExpiresAt         string          `json:"expires_at,omitempty"`
	SentAt            string          `json:"sent_at,omitempty"`
	CompletedAt       string          `json:"completed_at,omitempty"`
	SenderID          uuid.UUID       `json:"sender_id"`
	Metadata          json.RawMessage `json:"metadata"`
	DefaultLocale     string          `json:"default_locale"`
	CreatedAt         string          `json:"created_at"`
	UpdatedAt         string          `json:"updated_at"`
}

func toDocumentResponse(d *generated.Document) documentResponse {
	out := documentResponse{
		ID:                d.ID,
		OrgID:             d.OrgID,
		Name:              d.Name,
		Status:            d.Status,
		RoutingMode:       d.RoutingMode,
		SourceKind:        d.SourceKind,
		RequiresSignature: d.RequiresSignature,
		BlocksJSON:        d.BlocksJson,
		VariablesJSON:     d.VariablesJson,
		SenderID:          d.SenderID,
		Metadata:          d.Metadata,
		DefaultLocale:     d.DefaultLocale,
		CreatedAt:         d.CreatedAt.Time.Format(time.RFC3339),
		UpdatedAt:         d.UpdatedAt.Time.Format(time.RFC3339),
	}
	if d.TemplateID.Valid {
		out.TemplateID = uuidFromBytes(d.TemplateID.Bytes).String()
	}
	if d.PdfStorageKey.Valid {
		out.PDFStorageKey = d.PdfStorageKey.String
	}
	if len(d.PdfSha256) > 0 {
		out.PDFSHA256 = hex.EncodeToString(d.PdfSha256)
	}
	if d.FinalPdfKey.Valid {
		out.FinalPDFKey = d.FinalPdfKey.String
	}
	if d.AuditCertKey.Valid {
		out.AuditCertKey = d.AuditCertKey.String
	}
	if d.ExpiresAt.Valid {
		out.ExpiresAt = d.ExpiresAt.Time.Format(time.RFC3339)
	}
	if d.SentAt.Valid {
		out.SentAt = d.SentAt.Time.Format(time.RFC3339)
	}
	if d.CompletedAt.Valid {
		out.CompletedAt = d.CompletedAt.Time.Format(time.RFC3339)
	}
	return out
}

func uuidFromBytes(b [16]byte) uuid.UUID { return uuid.UUID(b) }

// createDocumentInput accepts either source kind. Block path uses blocks +
// variables; pdf path expects template_id pointing to a pdf-source template
// or a fresh upload (multi-step UX, week 2).
type createDocumentInput struct {
	Name          string          `json:"name"`
	TemplateID    string          `json:"template_id,omitempty"`
	SourceKind    string          `json:"source_kind"`
	BlocksJSON    json.RawMessage `json:"blocks_json,omitempty"`
	VariablesJSON json.RawMessage `json:"variables_json,omitempty"`
	ExpiresAt     string          `json:"expires_at,omitempty"`
}

func (s *Server) handleCreateDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	var in createDocumentInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if in.SourceKind != "blocks" && in.SourceKind != "pdf" {
		writeError(w, http.StatusBadRequest, "source_kind must be blocks or pdf")
		return
	}

	var templateID pgtype.UUID
	if in.TemplateID != "" {
		tid, err := uuid.Parse(in.TemplateID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid template_id")
			return
		}
		templateID = pgtype.UUID{Bytes: tid, Valid: true}
	}

	var expiresAt pgtype.Timestamptz
	if in.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, in.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "expires_at must be RFC3339")
			return
		}
		expiresAt = pgtype.Timestamptz{Time: t, Valid: true}
	}

	switch in.SourceKind {
	case "blocks":
		blocks := in.BlocksJSON
		vars := in.VariablesJSON
		// Instantiate from a blocks template: copy its content + variable
		// defaults into the new document so "New document" actually seeds the
		// agreement. The request can still override either by sending its own.
		if templateID.Valid && (len(blocks) == 0 || len(vars) == 0) {
			tpl, terr := s.Queries.GetTemplate(r.Context(), generated.GetTemplateParams{ID: uuid.UUID(templateID.Bytes), OrgID: u.OrgID})
			if terr != nil {
				writeError(w, http.StatusBadRequest, "template not found")
				return
			}
			if tpl.SourceKind != "blocks" {
				writeError(w, http.StatusBadRequest, "template is not a blocks template")
				return
			}
			if len(blocks) == 0 && len(tpl.BlocksJson) > 0 {
				blocks = tpl.BlocksJson
			}
			if len(vars) == 0 && len(tpl.VariablesJson) > 0 {
				vars = tpl.VariablesJson
			}
		}
		if len(blocks) == 0 {
			blocks = json.RawMessage(`{"version":1,"blocks":[]}`)
		}
		normalizedBlocks, err := blockschema.NormalizeTreeJSON(blocks)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid blocks_json: "+err.Error())
			return
		}
		blocks = normalizedBlocks
		if len(vars) == 0 {
			vars = json.RawMessage(`{}`)
		}
		if _, err := blockschema.ParseVariableValues(vars); err != nil {
			writeError(w, http.StatusBadRequest, "invalid variables_json: "+err.Error())
			return
		}
		d, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
			func(q *generated.Queries) (*generated.Document, error) {
				if err := s.Billing.LockDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
					return nil, err
				}
				doc, err := q.CreateBlocksDocument(r.Context(), generated.CreateBlocksDocumentParams{
					OrgID:         u.OrgID,
					TemplateID:    templateID,
					Name:          in.Name,
					BlocksJson:    blocks,
					VariablesJson: vars,
					SenderID:      u.UserID,
					ExpiresAt:     expiresAt,
				})
				if err != nil {
					return nil, err
				}
				if err := s.Billing.EnforceDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
					return nil, err
				}
				return doc, nil
			},
			func(d *generated.Document) audit.Entry {
				return audit.Entry{
					OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &d.ID,
					Kind:    audit.KindDocumentCreated,
					Payload: map[string]any{"name": d.Name, "source_kind": "blocks"},
				}
			},
		)
		if err != nil {
			if s.writeAuthoringQuotaError(w, err) {
				return
			}
			writeInternalErrorMsg(w, "create document failed", err)
			return
		}
		writeJSON(w, http.StatusCreated, toDocumentResponse(d))
	case "pdf":
		// For week 1 the PDF path requires an existing template (so we have
		// the storage key + sha already). Free-PDF document uploads come in
		// week 2 with the field designer.
		if !templateID.Valid {
			writeError(w, http.StatusBadRequest, "template_id required for source_kind=pdf in v1")
			return
		}
		tpl, err := s.Queries.GetTemplate(r.Context(), generated.GetTemplateParams{
			ID: uuidFromBytes(templateID.Bytes), OrgID: u.OrgID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "template not found")
			return
		}
		if err != nil || tpl.SourceKind != "pdf" || !tpl.PdfStorageKey.Valid {
			writeError(w, http.StatusBadRequest, "template is not a pdf-source template")
			return
		}
		rep, repErr := sanitize.SyntheticTemplateReport()
		if repErr != nil {
			writeInternalErrorMsg(w, "create metadata redaction report", repErr)
			return
		}
		d, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
			func(q *generated.Queries) (*generated.Document, error) {
				if err := s.Billing.LockDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
					return nil, err
				}
				d, err := q.CreatePDFDocument(r.Context(), generated.CreatePDFDocumentParams{
					OrgID:                       u.OrgID,
					TemplateID:                  templateID,
					Name:                        in.Name,
					PdfStorageKey:               tpl.PdfStorageKey,
					PdfSha256:                   tpl.PdfSha256,
					PdfStorageVersionID:         tpl.PdfStorageVersionID,
					EvidenceVersionPinsRequired: tpl.EvidenceVersionPinRequired,
					SenderID:                    u.UserID,
					ExpiresAt:                   expiresAt,
				})
				if err != nil {
					return nil, err
				}
				if err := q.UpdateMetadataRedactionReport(r.Context(), generated.UpdateMetadataRedactionReportParams{
					ID: d.ID, MetadataRedactionReport: rep,
				}); err != nil {
					return nil, err
				}
				if err := s.Billing.EnforceDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
					return nil, err
				}
				return d, nil
			},
			func(d *generated.Document) audit.Entry {
				return audit.Entry{
					OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &d.ID,
					Kind:    audit.KindDocumentCreated,
					Payload: map[string]any{"name": d.Name, "source_kind": "pdf"},
				}
			},
		)
		if err != nil {
			if s.writeAuthoringQuotaError(w, err) {
				return
			}
			writeInternalErrorMsg(w, "create document failed", err)
			return
		}
		writeJSON(w, http.StatusCreated, toDocumentResponse(d))
	}
}

func (s *Server) handleListDocuments(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	limit, offset := paginationFromQuery(r, 50, 500)

	var statusFilter []string
	if vs, ok := r.URL.Query()["status"]; ok && len(vs) > 0 {
		statusFilter = vs
	}

	rows, err := s.Queries.ListDocuments(r.Context(), generated.ListDocumentsParams{
		OrgID:   u.OrgID,
		Column2: statusFilter,
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list documents failed")
		return
	}
	out := make([]documentResponse, 0, len(rows))
	for _, d := range rows {
		out = append(out, toDocumentResponse(d))
	}
	total, _ := s.Queries.CountDocuments(r.Context(), generated.CountDocumentsParams{
		OrgID:   u.OrgID,
		Column2: statusFilter,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"documents": out,
		"total":     total,
		"limit":     limit,
		"offset":    offset,
	})
}

func (s *Server) handleGetDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	d, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get document failed")
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(d))
}

// GET /api/v1/documents/{id}/pdf
//
// Serves the original uploaded PDF for a pdf-source document so the field
// designer can render its pages in the browser. Session-authed + org-scoped.
func (s *Server) handleGetDocumentPDF(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	d, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get document failed")
		return
	}
	if !d.PdfStorageKey.Valid || d.PdfStorageKey.String == "" {
		writeError(w, http.StatusNotFound, "document has no source pdf")
		return
	}
	body, err := readDocumentArtifact(r.Context(), s.Storage, d, d.PdfStorageKey.String, d.PdfSha256, d.PdfStorageVersionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load pdf failed")
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "inline")
	_, _ = w.Write(body)
}

type updateDocumentInput struct {
	Name              string          `json:"name,omitempty"`
	BlocksJSON        json.RawMessage `json:"blocks_json,omitempty"`
	VariablesJSON     json.RawMessage `json:"variables_json,omitempty"`
	ExpiresAt         string          `json:"expires_at,omitempty"`
	DefaultLocale     string          `json:"default_locale,omitempty"`
	RequiresSignature *bool           `json:"requires_signature,omitempty"`
}

func (s *Server) handleUpdateDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in updateDocumentInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	existing, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get document failed")
		return
	}
	if existing.Status != "draft" {
		writeError(w, http.StatusConflict, "document not in draft state")
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	q := s.Queries.WithTx(tx)
	existing, err = q.GetDocumentForUpdate(r.Context(), generated.GetDocumentForUpdateParams{ID: id, OrgID: u.OrgID})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if existing.Status != "draft" {
		writeError(w, http.StatusConflict, "document not in draft state")
		return
	}

	// Block updates only valid for block-source documents.
	if existing.SourceKind == "blocks" && (len(in.BlocksJSON) > 0 || len(in.VariablesJSON) > 0) {
		blocks := in.BlocksJSON
		if len(blocks) == 0 {
			blocks = existing.BlocksJson
		}
		blocks, err = blockschema.NormalizeTreeJSON(blocks)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid blocks_json: "+err.Error())
			return
		}
		vars := in.VariablesJSON
		if len(vars) == 0 {
			vars = existing.VariablesJson
		}
		if _, err := blockschema.ParseVariableValues(vars); err != nil {
			writeError(w, http.StatusBadRequest, "invalid variables_json: "+err.Error())
			return
		}
		if _, err := q.UpdateDocumentBlocks(r.Context(), generated.UpdateDocumentBlocksParams{
			ID:            id,
			OrgID:         u.OrgID,
			BlocksJson:    blocks,
			VariablesJson: vars,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "update blocks failed")
			return
		}
	}

	// Metadata path: name, expires_at. Merge in Go because the SQL uses
	// COALESCE on positional args and pgx doesn't pass Go zero-value strings
	// as NULL.
	name := existing.Name
	if in.Name != "" {
		name = in.Name
	}
	expiresArg := existing.ExpiresAt
	if in.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, in.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "expires_at must be RFC3339")
			return
		}
		expiresArg = pgtype.Timestamptz{Time: t, Valid: true}
	}
	d, err := q.UpdateDocumentMetadata(r.Context(), generated.UpdateDocumentMetadataParams{
		ID:        id,
		OrgID:     u.OrgID,
		Name:      name,
		ExpiresAt: expiresArg,
		Metadata:  existing.Metadata,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update document failed")
		return
	}

	// Document-level default signing language: the sender's "send this in
	// Swedish" choice. New recipients inherit it (see handleCreateRecipient).
	if in.DefaultLocale != "" && in.DefaultLocale != d.DefaultLocale {
		d, err = q.SetDocumentDefaultLocale(r.Context(), generated.SetDocumentDefaultLocaleParams{
			ID:            id,
			OrgID:         u.OrgID,
			DefaultLocale: in.DefaultLocale,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "update default language failed")
			return
		}
	}

	// Signature mode: draft-only toggle between signature-required and
	// acknowledgement (view/accept). Locked once sent.
	if in.RequiresSignature != nil && *in.RequiresSignature != d.RequiresSignature {
		d, err = q.SetDocumentRequiresSignature(r.Context(), generated.SetDocumentRequiresSignatureParams{
			ID:                id,
			OrgID:             u.OrgID,
			RequiresSignature: *in.RequiresSignature,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "update signature mode failed")
			return
		}
	}

	pending, err := s.Audit.LogTx(r.Context(), tx, audit.Entry{
		OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &d.ID,
		Kind: audit.KindDocumentUpdated,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeInternalError(w, err)
		return
	}
	s.Audit.Publish(pending)
	writeJSON(w, http.StatusOK, toDocumentResponse(d))
}

type changeRequestResponse struct {
	ID             string `json:"id"`
	Message        string `json:"message"`
	Status         string `json:"status"`
	Resolution     string `json:"resolution,omitempty"`
	BlockID        string `json:"block_id,omitempty"`
	Quote          string `json:"quote,omitempty"`
	Context        string `json:"context,omitempty"`
	Proposed       string `json:"proposed,omitempty"`
	RecipientName  string `json:"recipient_name,omitempty"`
	RecipientEmail string `json:"recipient_email,omitempty"`
	CreatedAt      string `json:"created_at"`
}

// handleListChangeRequests returns the change requests a signer raised, so the
// sender can read what was asked before revising.
func (s *Server) handleListChangeRequests(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if _, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID}); err != nil {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	rows, err := s.Queries.ListChangeRequests(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list change requests failed")
		return
	}
	out := make([]changeRequestResponse, 0, len(rows))
	for _, cr := range rows {
		resp := changeRequestResponse{
			ID:        cr.ID.String(),
			Message:   cr.Message,
			Status:    cr.Status,
			BlockID:   cr.BlockID,
			Quote:     cr.Quote,
			Context:   cr.Context,
			Proposed:  cr.Proposed,
			CreatedAt: cr.CreatedAt.Time.Format(time.RFC3339),
		}
		if cr.Resolution.Valid {
			resp.Resolution = cr.Resolution.String
		}
		if cr.RecipientName.Valid {
			resp.RecipientName = cr.RecipientName.String
		}
		if cr.RecipientEmail.Valid {
			resp.RecipientEmail = cr.RecipientEmail.String
		}
		out = append(out, resp)
	}
	writeJSON(w, http.StatusOK, map[string]any{"change_requests": out})
}

func (s *Server) resolveChangeRequest(w http.ResponseWriter, r *http.Request, approve bool) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	crID, ok := parseUUIDParam(w, r, "crid")
	if !ok {
		return
	}
	if _, err := s.Sign.ResolveChange(r.Context(), u.OrgID, id, crID, approve); err != nil {
		writeError(w, http.StatusInternalServerError, "resolve change request failed")
		return
	}
	resolution := "denied"
	if approve {
		resolution = "approved"
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "resolved", "resolution": resolution})
}

func (s *Server) handleApproveChangeRequest(w http.ResponseWriter, r *http.Request) {
	s.resolveChangeRequest(w, r, true)
}

func (s *Server) handleDenyChangeRequest(w http.ResponseWriter, r *http.Request) {
	s.resolveChangeRequest(w, r, false)
}

type changeApprovalModeInput struct {
	Mode string `json:"mode"`
}

// handleSetChangeApprovalMode sets the org-wide behaviour for approving inline
// change requests: 'accept' (record acceptance, apply on Revise) or 'auto_apply'
// (swap the marked text immediately).
func (s *Server) handleSetChangeApprovalMode(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	var in changeApprovalModeInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.Mode != "accept" && in.Mode != "auto_apply" {
		writeError(w, http.StatusBadRequest, "mode must be accept or auto_apply")
		return
	}
	if _, err := s.Queries.SetOrgChangeApprovalMode(r.Context(), generated.SetOrgChangeApprovalModeParams{ID: u.OrgID, ChangeApprovalMode: in.Mode}); err != nil {
		writeError(w, http.StatusInternalServerError, "update setting failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"change_approval_mode": in.Mode})
}

// handleReviseDocument reopens a document that a signer paused with a change
// request, returning it to draft so the sender can edit and re-send.
func (s *Server) handleReviseDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	doc, err := s.Sign.Revise(r.Context(), u.OrgID, id)
	if err != nil {
		if errors.Is(err, sign.ErrEnvelopeTransitionUnsupported) {
			writeError(w, http.StatusConflict, "envelope revision is not supported; void the envelope and create a new draft instead")
			return
		}
		if errors.Is(err, sign.ErrNotRevisable) {
			writeError(w, http.StatusConflict, "document is not awaiting revision")
			return
		}
		if errors.Is(err, sign.ErrRevisionWouldDestroyEvidence) {
			writeError(w, http.StatusConflict, "revision blocked because this ceremony already contains captured legal evidence; void and create a superseding document instead")
			return
		}
		writeError(w, http.StatusInternalServerError, "revise failed")
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

type commentResponse struct {
	ID         string `json:"id"`
	AuthorName string `json:"author_name"`
	AuthorSide string `json:"author_side"`
	Body       string `json:"body"`
	CreatedAt  string `json:"created_at"`
}

func toCommentResponse(c *generated.DocumentComment) commentResponse {
	return commentResponse{
		ID:         c.ID.String(),
		AuthorName: c.AuthorName,
		AuthorSide: c.AuthorSide,
		Body:       c.Body,
		CreatedAt:  c.CreatedAt.Time.Format(time.RFC3339),
	}
}

func toCommentResponses(rows []*generated.DocumentComment) []commentResponse {
	out := make([]commentResponse, 0, len(rows))
	for _, c := range rows {
		out = append(out, toCommentResponse(c))
	}
	return out
}

func (s *Server) handleListComments(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if _, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID}); err != nil {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	rows, err := s.Queries.ListComments(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list comments failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"comments": toCommentResponses(rows)})
}

type createCommentInput struct {
	Body string `json:"body"`
}

func (s *Server) handleCreateComment(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in createCommentInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	name := u.Email
	if usr, uerr := s.Queries.GetUser(r.Context(), u.UserID); uerr == nil && usr.Name != "" {
		name = usr.Name
	}
	c, err := s.Sign.SenderComment(r.Context(), u.OrgID, id, u.UserID, name, in.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, toCommentResponse(c))
}

func (s *Server) handleDeleteDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	// GetDocumentByID includes already-soft-deleted rows. That makes object
	// cleanup retryable if PostgreSQL accepted the delete but MinIO was
	// temporarily unavailable during the first request.
	doc, err := s.Queries.GetDocumentByID(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && doc.OrgID != u.OrgID) {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get document failed")
		return
	}
	if doc.Status != "draft" {
		writeError(w, http.StatusConflict, "only draft documents can be deleted")
		return
	}
	if !doc.DeletedAt.Valid {
		if err := s.Queries.DeleteDraftDocument(r.Context(), generated.DeleteDraftDocumentParams{ID: id, OrgID: u.OrgID}); err != nil {
			writeError(w, http.StatusInternalServerError, "delete document failed")
			return
		}
		// DeleteDraftDocument is an :exec query and therefore reports nil even
		// when a concurrent send changed the status and the guarded UPDATE
		// matched zero rows. Re-read before deleting bytes so that race cannot
		// remove the source underneath an active agreement.
		doc, err = s.Queries.GetDocumentByID(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "verify document delete failed")
			return
		}
		if !doc.DeletedAt.Valid {
			writeError(w, http.StatusConflict, "document changed state before it could be deleted")
			return
		}
	}

	keys := draftSourceObjectKeys(doc)
	if len(keys) > 0 && s.Storage == nil {
		writeError(w, http.StatusServiceUnavailable, "storage unavailable for document cleanup")
		return
	}
	for _, key := range keys {
		if err := deleteObjectDetached(r.Context(), s.Storage, key); err != nil {
			writeInternalErrorMsg(w, "delete document source failed; retry the delete", err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	// Authorization: ensure the document is in the caller's org.
	if _, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	rows, err := s.Queries.ListEventsByDocument(r.Context(), generated.ListEventsByDocumentParams{
		DocumentID: pgtype.UUID{Bytes: docID, Valid: true},
		Limit:      500,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list events failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": rows})
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
