// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/db/generated"
	recipientrules "github.com/bright-interaction/hash/internal/recipients"
)

// engagementBlockDTO is the wire shape per block in the engagement summary.
type engagementBlockDTO struct {
	BlockID      string `json:"block_id"`
	TotalViews   int32  `json:"total_views"`
	TotalDwellMs int64  `json:"total_dwell_ms"`
	AvgDwellMs   int32  `json:"avg_dwell_ms"`
	LastEventAt  string `json:"last_event_at"`
}

// GET /api/v1/documents/{id}/engagement
//
// Returns the rolled-up per-block dwell + view counts. Only visible to
// sender-side session users. Aggregates only, never per-recipient when
// the doc has fewer than 2 recipients (privacy guardrail: a sender
// could otherwise surveil reading in real time, GDPR proportionality).
func (s *Server) handleEngagement(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	doc, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: sess.OrgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	recipients, err := s.Queries.ListRecipientsByDocument(r.Context(), doc.ID)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	// Privacy gate: single-recipient docs only expose legacy engagement after
	// the recipient completed either the signature or acknowledgement ceremony,
	// so the sender cannot watch their activity in real time.
	allResponded := true
	for _, rc := range recipients {
		if !recipientrules.HasTerminalResponse(rc.Status) {
			allResponded = false
			break
		}
	}
	if len(recipients) <= 1 && !allResponded {
		writeJSON(w, http.StatusOK, map[string]any{
			"blocks":        []any{},
			"privacy_gated": true,
			"reason":        "single-recipient engagement is hidden until the recipient responds",
		})
		return
	}

	rows, err := s.Queries.ListEngagementByDocument(r.Context(), doc.ID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]engagementBlockDTO, 0, len(rows))
	for _, row := range rows {
		out = append(out, engagementBlockDTO{
			BlockID:      row.BlockID,
			TotalViews:   row.TotalViews,
			TotalDwellMs: row.TotalDwellMs,
			AvgDwellMs:   row.AvgDwellMs,
			LastEventAt:  row.LastEventAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"blocks":          out,
		"recipient_count": len(recipients),
		"privacy_gated":   false,
	})
}

// GET /api/v1/documents/{id}/telemetry-stream
//
// Raw signer-side telemetry feed (block.viewed, page.scroll, click,
// session). Phase 8.8 owns the /timeline name now; the signer-side
// telemetry stream gets a distinct path so the audit timeline can take
// its rightful place on /timeline.
func (s *Server) handleTelemetryStream(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if _, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: sess.OrgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	recipients, err := s.Queries.ListRecipientsByDocument(r.Context(), docID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	allResponded := true
	for _, rc := range recipients {
		if !recipientrules.HasTerminalResponse(rc.Status) {
			allResponded = false
			break
		}
	}
	if len(recipients) <= 1 && !allResponded {
		writeJSON(w, http.StatusOK, map[string]any{
			"events":        []any{},
			"privacy_gated": true,
		})
		return
	}
	rows, err := s.Queries.ListTelemetryByDocument(r.Context(), generated.ListTelemetryByDocumentParams{
		DocumentID: docID,
		Limit:      200,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	events := make([]map[string]any, 0, len(rows))
	for _, ev := range rows {
		entry := map[string]any{
			"id":         ev.ID.String(),
			"kind":       ev.Kind,
			"payload":    json.RawMessage(ev.PayloadJson),
			"ua_class":   ev.UaClass,
			"created_at": ev.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		}
		if ev.BlockID.Valid {
			entry["block_id"] = ev.BlockID.String
		}
		if ev.IpGeo != "" {
			entry["country"] = ev.IpGeo
		}
		events = append(events, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "privacy_gated": false})
}
