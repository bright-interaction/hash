package handler

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/brightinteraction/hash/internal/billing"
	"github.com/brightinteraction/hash/internal/eidas"
	"github.com/brightinteraction/hash/internal/send"
)

// Document lifecycle handlers. All the actual work (quota gate, variable
// freeze, eIDAS guard, magic-token minting WITH expiry, reminders, audit,
// email) lives in internal/send.Engine so the REST, MCP, and worker surfaces
// share one implementation and the invariants can't drift between them.

type sendDocumentResponse struct {
	Status string        `json:"status"`
	Links  []signingLink `json:"links"`
}

type signingLink struct {
	RecipientID uuid.UUID `json:"recipient_id"`
	Email       string    `json:"email"`
	Name        string    `json:"name"`
	Role        string    `json:"role"`
	URL         string    `json:"url"`
}

func (s *Server) handleSendDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	res, err := s.Send.Send(r.Context(), send.Actor{
		UserID: &u.UserID, OrgID: u.OrgID, Email: u.Email, IP: clientIP(r), Via: "rest",
	}, docID)
	if err != nil {
		s.writeSendError(w, err)
		return
	}
	out := sendDocumentResponse{Status: res.Status, Links: make([]signingLink, 0, len(res.Links))}
	for _, l := range res.Links {
		out.Links = append(out.Links, signingLink{RecipientID: l.RecipientID, Email: l.Email, Name: l.Name, Role: l.Role, URL: l.URL})
	}
	writeJSON(w, http.StatusOK, out)
}

// writeSendError maps the engine's typed errors to the REST responses the UI
// expects: 402 + upgrade_url for quota, 409 + tier detail for an eIDAS block.
func (s *Server) writeSendError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, send.ErrDocumentNotFound):
		writeError(w, http.StatusNotFound, "document not found")
	case errors.Is(err, send.ErrNotDraft):
		writeError(w, http.StatusConflict, "document not in draft state")
	case errors.Is(err, send.ErrNoSigners):
		writeError(w, http.StatusBadRequest, "document needs at least one signer recipient before send")
	case errors.Is(err, send.ErrNoRecipients):
		writeError(w, http.StatusBadRequest, "document needs at least one recipient before send")
	case errors.Is(err, billing.ErrQuotaExceeded):
		writeJSON(w, http.StatusPaymentRequired, map[string]any{
			"error":       err.Error(),
			"upgrade_url": "/settings/billing",
		})
	default:
		var guardErr *eidas.GuardError
		if errors.As(err, &guardErr) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":         err.Error(),
				"required_tier": guardErr.Decision.RequiredTier,
				"current_tier":  guardErr.CurrentTier,
				"matched_rules": guardErr.Decision.MatchedRules,
			})
			return
		}
		writeInternalError(w, err)
	}
}

type voidDocumentInput struct {
	Reason string `json:"reason"`
}

func (s *Server) handleVoidDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in voidDocumentInput
	_ = decodeJSON(r, &in)
	err := s.Send.Void(r.Context(), send.Actor{
		UserID: &u.UserID, OrgID: u.OrgID, Email: u.Email, IP: clientIP(r), Via: "rest",
	}, docID, in.Reason)
	if err != nil {
		switch {
		case errors.Is(err, send.ErrDocumentNotFound):
			writeError(w, http.StatusNotFound, "document not found")
		case errors.Is(err, send.ErrAlreadyFinalised):
			writeError(w, http.StatusConflict, "document already finalised")
		default:
			writeInternalError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "voided"})
}
