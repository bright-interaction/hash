package handler

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/config"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/dispatch"
)

type webhookEndpointResponse struct {
	ID               uuid.UUID `json:"id"`
	URL              string    `json:"url"`
	EventsSubscribed []string  `json:"events_subscribed"`
	Active           bool      `json:"active"`
	CreatedAt        string    `json:"created_at"`
	// Secret is populated on the CREATE response only. Subsequent
	// reads return the empty string so a stolen list cannot leak the
	// signing key.
	Secret string `json:"secret,omitempty"`
}

// mintWebhookSecret generates a 32-byte cryptographically random key
// encoded as 64 lowercase hex chars. Sized to match HMAC-SHA256 best
// practice (256-bit secret for a 256-bit MAC).
func mintWebhookSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

type createWebhookInput struct {
	URL    string   `json:"url"`
	Events []string `json:"events_subscribed"`
}

func (s *Server) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	var in createWebhookInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.URL == "" {
		writeError(w, http.StatusBadRequest, "url required")
		return
	}
	// SSRF guard at registration: reject URLs that resolve to internal
	// addresses before they ever land in the delivery queue.
	if err := dispatch.ValidateWebhookURL(in.URL, config.IsLocalDevelopment(s.PublicURL)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(in.Events) == 0 {
		writeError(w, http.StatusBadRequest, "events_subscribed required (at least one)")
		return
	}
	for _, ev := range in.Events {
		switch ev {
		case "document.sent", "document.viewed", "document.signed",
			"document.completed", "document.declined", "document.voided",
			"document.expired", "recipient.bounced":
		default:
			writeError(w, http.StatusBadRequest, "unknown event kind: "+ev)
			return
		}
	}

	secret, err := mintWebhookSecret()
	if err != nil {
		writeInternalErrorMsg(w, "secret generation failed", err)
		return
	}
	row, err := s.Queries.CreateWebhookEndpoint(r.Context(), generated.CreateWebhookEndpointParams{
		OrgID:            u.OrgID,
		Url:              in.URL,
		SecretRef:        "per-endpoint",
		Secret:           secret,
		EventsSubscribed: in.Events,
	})
	if err != nil {
		writeInternalErrorMsg(w, "create webhook failed", err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: u.OrgID, ActorUserID: &u.UserID,
		Kind:    "webhook.created",
		IP:      clientIP(r),
		Payload: map[string]any{"endpoint_id": row.ID, "url": row.Url, "events": in.Events},
	})
	// Secret is returned ONCE on create. Subsequent reads omit it so a
	// list endpoint cannot leak the signing key.
	writeJSON(w, http.StatusCreated, webhookEndpointResponse{
		ID:               row.ID,
		URL:              row.Url,
		EventsSubscribed: append([]string{}, row.EventsSubscribed...),
		Active:           row.Active,
		CreatedAt:        row.CreatedAt.Time.Format(time.RFC3339),
		Secret:           secret,
	})
}

func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	rows, err := s.Queries.ListWebhookEndpointsByOrg(r.Context(), u.OrgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list webhooks failed")
		return
	}
	out := make([]webhookEndpointResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, webhookEndpointResponse{
			ID:               row.ID,
			URL:              row.Url,
			EventsSubscribed: append([]string{}, row.EventsSubscribed...),
			Active:           row.Active,
			CreatedAt:        row.CreatedAt.Time.Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"webhooks": out})
}

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if err := s.Queries.DeleteWebhookEndpoint(r.Context(), generated.DeleteWebhookEndpointParams{
		ID: id, OrgID: u.OrgID,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: u.OrgID, ActorUserID: &u.UserID,
		Kind:    "webhook.deleted",
		IP:      clientIP(r),
		Payload: map[string]any{"endpoint_id": id},
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleListWebhookDeliveries returns the recent delivery log for a single
// endpoint (sender-only view). Up to 200 rows.
func (s *Server) handleListWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}

	// Verify the endpoint is in the caller's org first.
	endpoints, err := s.Queries.ListWebhookEndpointsByOrg(r.Context(), u.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	found := false
	for _, ep := range endpoints {
		if ep.ID == id {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "webhook endpoint not found")
		return
	}

	rows, err := s.Queries.ListDeliveriesByEndpoint(r.Context(), generated.ListDeliveriesByEndpointParams{
		EndpointID: id, Limit: 200,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list deliveries failed")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, d := range rows {
		entry := map[string]any{
			"id":         d.ID,
			"event_id":   d.EventID,
			"status":     d.Status,
			"attempts":   d.Attempts,
			"created_at": d.CreatedAt.Time.Format(time.RFC3339),
		}
		if d.LastStatusCode.Valid {
			entry["last_status_code"] = d.LastStatusCode.Int32
		}
		if d.LastError.Valid {
			entry["last_error"] = d.LastError.String
		}
		out = append(out, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"deliveries": out})
}

var (
	_ = errors.New
)
