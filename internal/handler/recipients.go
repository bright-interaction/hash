// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/recipients"
)

var (
	errRecipientNotFound       = errors.New("recipient not found")
	errRecipientDocumentLocked = errors.New("document not editable (must be draft)")
)

type recipientResponse struct {
	ID            uuid.UUID `json:"id"`
	DocumentID    uuid.UUID `json:"document_id"`
	Role          string    `json:"role"`
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	OrderIndex    int32     `json:"order_index"`
	Locale        string    `json:"locale"`
	Status        string    `json:"status"`
	SentAt        string    `json:"sent_at,omitempty"`
	FirstViewedAt string    `json:"first_viewed_at,omitempty"`
	SignedAt      string    `json:"signed_at,omitempty"`
	CreatedAt     string    `json:"created_at"`
}

func toRecipientResponse(r *generated.Recipient) recipientResponse {
	out := recipientResponse{
		ID:         r.ID,
		DocumentID: r.DocumentID,
		Role:       r.Role,
		Email:      r.Email,
		Name:       r.Name,
		OrderIndex: r.OrderIndex,
		Locale:     r.Locale,
		Status:     r.Status,
		CreatedAt:  r.CreatedAt.Time.Format(time.RFC3339),
	}
	if r.SentAt.Valid {
		out.SentAt = r.SentAt.Time.Format(time.RFC3339)
	}
	if r.FirstViewedAt.Valid {
		out.FirstViewedAt = r.FirstViewedAt.Time.Format(time.RFC3339)
	}
	if r.SignedAt.Valid {
		out.SignedAt = r.SignedAt.Time.Format(time.RFC3339)
	}
	return out
}

type createRecipientInput struct {
	Role       string `json:"role"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	OrderIndex int32  `json:"order_index"`
	Locale     string `json:"locale"`
}

func (s *Server) handleListRecipients(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if !s.assertDocumentInOrg(w, r, docID, u) {
		return
	}
	rows, err := s.Queries.ListRecipientsByDocument(r.Context(), docID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list recipients failed")
		return
	}
	out := make([]recipientResponse, 0, len(rows))
	for _, rec := range rows {
		out = append(out, toRecipientResponse(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{"recipients": out})
}

func (s *Server) handleCreateRecipient(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	doc, ok := s.requireDraftDocument(w, r, docID, u)
	if !ok {
		return
	}

	var in createRecipientInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.Email == "" || in.Name == "" {
		writeError(w, http.StatusBadRequest, "email and name required")
		return
	}
	role := in.Role
	if role == "" {
		role = "signer"
	}
	// Inherit the document's default signing language unless this recipient
	// was given an explicit one. This is the cascade behind the sender's
	// "send this document in Swedish" choice.
	locale := in.Locale
	if locale == "" {
		locale = doc.DefaultLocale
	}
	if locale == "" {
		locale = "en"
	}
	values, err := recipients.Normalize(recipients.Values{
		Email: in.Email, Name: in.Name, Role: role, OrderIndex: in.OrderIndex, Locale: locale,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := recipients.ValidateResponseRole(values.Role); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, hash, err := auth.MintMagicToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token mint failed")
		return
	}

	rec, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (*generated.Recipient, error) {
			if err := s.Billing.LockDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
				return nil, err
			}
			rec, err := q.CreateRecipient(r.Context(), generated.CreateRecipientParams{
				DocumentID:          docID,
				Role:                values.Role,
				Email:               values.Email,
				Name:                values.Name,
				OrderIndex:          values.OrderIndex,
				Locale:              values.Locale,
				MagicTokenHash:      hash,
				MagicTokenExpiresAt: computeMagicTokenExpiry(doc, time.Now()),
			})
			if err != nil {
				return nil, err
			}
			if err := s.Billing.EnforceDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
				return nil, err
			}
			return rec, nil
		},
		func(rec *generated.Recipient) audit.Entry {
			return audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &docID, RecipientID: &rec.ID,
				Kind:    audit.KindRecipientCreated,
				Payload: map[string]any{"email": rec.Email, "name": rec.Name, "role": rec.Role},
			}
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "document not editable (must be draft)")
		return
	}
	if err != nil {
		if s.writeAuthoringQuotaError(w, err) {
			return
		}
		writeInternalErrorMsg(w, "create recipient failed", err)
		return
	}

	writeJSON(w, http.StatusCreated, toRecipientResponse(rec))
}

type updateRecipientInput struct {
	Email      *string `json:"email,omitempty"`
	Name       *string `json:"name,omitempty"`
	Role       *string `json:"role,omitempty"`
	OrderIndex *int32  `json:"order_index,omitempty"`
	Locale     *string `json:"locale,omitempty"`
}

func (s *Server) handleUpdateRecipient(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	rid, ok := parseUUIDParam(w, r, "rid")
	if !ok {
		return
	}
	if _, ok := s.requireDraftDocument(w, r, docID, u); !ok {
		return
	}
	var in updateRecipientInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	rec, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (*generated.Recipient, error) {
			doc, err := q.GetDocumentForUpdate(r.Context(), generated.GetDocumentForUpdateParams{ID: docID, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errRecipientNotFound
			}
			if err != nil {
				return nil, err
			}
			if doc.Status != "draft" {
				return nil, errRecipientDocumentLocked
			}
			existing, err := q.GetRecipient(r.Context(), generated.GetRecipientParams{ID: rid, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errRecipientNotFound
			}
			if err != nil {
				return nil, err
			}
			if existing.DocumentID != docID {
				return nil, errRecipientNotFound
			}
			values, err := normalizeRecipientUpdate(existing, in)
			if err != nil {
				return nil, err
			}
			return q.UpdateRecipient(r.Context(), generated.UpdateRecipientParams{
				ID: rid, DocumentID: docID, Email: values.Email, Name: values.Name,
				Role: values.Role, OrderIndex: values.OrderIndex, Locale: values.Locale,
			})
		},
		func(updated *generated.Recipient) audit.Entry {
			return audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &docID, RecipientID: &updated.ID,
				Kind:    audit.KindRecipientUpdated,
				Payload: map[string]any{"email": updated.Email, "name": updated.Name, "role": updated.Role},
			}
		},
	)
	if errors.Is(err, errRecipientDocumentLocked) || errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "document not editable (must be draft)")
		return
	}
	if errors.Is(err, errRecipientNotFound) {
		writeError(w, http.StatusNotFound, "recipient not found")
		return
	}
	var validationErr *recipients.ValidationError
	if errors.As(err, &validationErr) {
		writeError(w, http.StatusBadRequest, validationErr.Error())
		return
	}
	if err != nil {
		writeInternalErrorMsg(w, "update recipient failed", err)
		return
	}
	writeJSON(w, http.StatusOK, toRecipientResponse(rec))
}

func (s *Server) handleDeleteRecipient(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	rid, ok := parseUUIDParam(w, r, "rid")
	if !ok {
		return
	}
	if _, ok := s.requireDraftDocument(w, r, docID, u); !ok {
		return
	}
	_, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (*generated.Recipient, error) {
			doc, err := q.GetDocumentForUpdate(r.Context(), generated.GetDocumentForUpdateParams{ID: docID, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errRecipientNotFound
			}
			if err != nil {
				return nil, err
			}
			if doc.Status != "draft" {
				return nil, errRecipientDocumentLocked
			}
			existing, err := q.GetRecipient(r.Context(), generated.GetRecipientParams{ID: rid, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) || (err == nil && existing.DocumentID != docID) {
				return nil, errRecipientNotFound
			}
			if err != nil {
				return nil, err
			}
			if _, err := q.DeleteRecipient(r.Context(), generated.DeleteRecipientParams{ID: rid, DocumentID: docID}); err != nil {
				return nil, err
			}
			return existing, nil
		},
		func(deleted *generated.Recipient) audit.Entry {
			return audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &docID, RecipientID: &deleted.ID,
				Kind:    audit.KindRecipientDeleted,
				Payload: map[string]any{"email": deleted.Email, "name": deleted.Name, "role": deleted.Role},
			}
		},
	)
	if errors.Is(err, errRecipientDocumentLocked) || errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "document not editable (must be draft)")
		return
	}
	if errors.Is(err, errRecipientNotFound) {
		writeError(w, http.StatusNotFound, "recipient not found")
		return
	}
	if err != nil {
		writeInternalErrorMsg(w, "delete recipient failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func normalizeRecipientUpdate(existing *generated.Recipient, in updateRecipientInput) (recipients.Values, error) {
	values := recipients.Values{
		Email: existing.Email, Name: existing.Name, Role: existing.Role,
		OrderIndex: existing.OrderIndex, Locale: existing.Locale,
	}
	if in.Email != nil {
		values.Email = *in.Email
	}
	if in.Name != nil {
		values.Name = *in.Name
	}
	if in.Role != nil {
		values.Role = *in.Role
	}
	if in.OrderIndex != nil {
		values.OrderIndex = *in.OrderIndex
	}
	if in.Locale != nil {
		values.Locale = *in.Locale
	}
	normalized, err := recipients.Normalize(values)
	if err != nil {
		return recipients.Values{}, err
	}
	if err := recipients.ValidateResponseRole(normalized.Role); err != nil {
		return recipients.Values{}, err
	}
	return normalized, nil
}

// requireDraftDocument provides a friendly HTTP error before authoring work,
// while every write query repeats the status predicate atomically to close a
// concurrent send race.
func (s *Server) requireDraftDocument(w http.ResponseWriter, r *http.Request, docID uuid.UUID, u auth.SessionUser) (*generated.Document, bool) {
	doc, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "document not found")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return nil, false
	}
	if doc.Status != "draft" {
		writeError(w, http.StatusConflict, "document not editable (must be draft)")
		return nil, false
	}
	return doc, true
}

// assertDocumentInOrg verifies the document is in the user's org so we can't
// read or mutate cross-tenant rows. Writes 404 on miss, 500 on lookup error.
func (s *Server) assertDocumentInOrg(w http.ResponseWriter, r *http.Request, docID uuid.UUID, u auth.SessionUser) bool {
	if _, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return false
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return false
	}
	return true
}
