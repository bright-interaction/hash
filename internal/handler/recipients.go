package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/db/generated"
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
	if !s.assertDocumentInOrg(w, r, docID, u) {
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
	_, hash, err := auth.MintMagicToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token mint failed")
		return
	}

	doc, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID})
	if err != nil {
		writeError(w, http.StatusNotFound, "document not found")
		return
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

	rec, err := s.Queries.CreateRecipient(r.Context(), generated.CreateRecipientParams{
		DocumentID:          docID,
		Role:                role,
		Email:               in.Email,
		Name:                in.Name,
		OrderIndex:          in.OrderIndex,
		Locale:              locale,
		MagicTokenHash:      hash,
		MagicTokenExpiresAt: computeMagicTokenExpiry(doc, time.Now()),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create recipient failed: "+err.Error())
		return
	}

	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &docID, RecipientID: &rec.ID,
		Kind:    audit.KindRecipientInvited,
		Payload: map[string]any{"email": rec.Email, "name": rec.Name, "role": rec.Role},
	})
	writeJSON(w, http.StatusCreated, toRecipientResponse(rec))
}

type updateRecipientInput struct {
	Email      string `json:"email,omitempty"`
	Name       string `json:"name,omitempty"`
	Role       string `json:"role,omitempty"`
	OrderIndex *int32 `json:"order_index,omitempty"`
	Locale     string `json:"locale,omitempty"`
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
	if !s.assertDocumentInOrg(w, r, docID, u) {
		return
	}
	var in updateRecipientInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	// Read-then-merge in Go: COALESCE($x, col) treats empty string as a real
	// value because pgx won't pass "" as NULL.
	existing, err := s.Queries.GetRecipient(r.Context(), generated.GetRecipientParams{
		ID: rid, OrgID: u.OrgID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "recipient not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	email := existing.Email
	if in.Email != "" {
		email = in.Email
	}
	name := existing.Name
	if in.Name != "" {
		name = in.Name
	}
	role := existing.Role
	if in.Role != "" {
		role = in.Role
	}
	orderIdx := existing.OrderIndex
	if in.OrderIndex != nil {
		orderIdx = *in.OrderIndex
	}
	locale := existing.Locale
	if in.Locale != "" {
		locale = in.Locale
	}
	rec, err := s.Queries.UpdateRecipient(r.Context(), generated.UpdateRecipientParams{
		ID:         rid,
		DocumentID: docID,
		Email:      email,
		Name:       name,
		Role:       role,
		OrderIndex: orderIdx,
		Locale:     locale,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "recipient not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update recipient failed")
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
	if !s.assertDocumentInOrg(w, r, docID, u) {
		return
	}
	if err := s.Queries.DeleteRecipient(r.Context(), generated.DeleteRecipientParams{
		ID: rid, DocumentID: docID,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "delete recipient failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
