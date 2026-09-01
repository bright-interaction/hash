// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	recipientrules "github.com/bright-interaction/hash/internal/recipients"
)

// registerEngagementTools mounts the Phase 8.3 read surface for agents.
// get_document_engagement returns the per-block dwell rollup;
// get_document_telemetry_stream returns recent raw signer-side
// telemetry events. Both honour the same single-recipient privacy gate
// the REST endpoints enforce. Phase 8.8 owns the get_document_timeline
// tool name now (it returns audit events; see tools_timeline.go).
func registerEngagementTools(s *Server, d Deps) {
	s.RegisterTool(ToolDef{
		Name:        "get_document_engagement",
		Description: "Return the retained legacy per-block dwell/view rollup for a document. New signer analytics are disabled. Privacy gate: for a one-recipient document, legacy data stays hidden until the recipient signs or accepts (GDPR proportionality).",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
		}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			if _, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID}); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("document not found")
				}
				return nil, err
			}
			recipients, err := d.Queries.ListRecipientsByDocument(r.Context(), id)
			if err != nil {
				return nil, err
			}
			allResponded := true
			for _, rc := range recipients {
				if !recipientrules.HasTerminalResponse(rc.Status) {
					allResponded = false
					break
				}
			}
			if len(recipients) <= 1 && !allResponded {
				return map[string]any{
					"blocks":        []any{},
					"privacy_gated": true,
					"reason":        "single-recipient engagement is hidden until the recipient responds",
				}, nil
			}
			rows, err := d.Queries.ListEngagementByDocument(r.Context(), id)
			if err != nil {
				return nil, err
			}
			out := make([]map[string]any, 0, len(rows))
			for _, row := range rows {
				out = append(out, map[string]any{
					"block_id":       row.BlockID,
					"total_views":    row.TotalViews,
					"total_dwell_ms": row.TotalDwellMs,
					"avg_dwell_ms":   row.AvgDwellMs,
					"last_event_at":  row.LastEventAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
				})
			}
			return map[string]any{
				"blocks":          out,
				"recipient_count": len(recipients),
				"privacy_gated":   false,
			}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "get_document_telemetry_stream",
		Description: "Return retained legacy signer-side telemetry events for a document. New signer analytics are disabled. Up to 200 by default, max 500; the same sign-or-accept single-recipient privacy gate as get_document_engagement applies. Phase 8.8 owns get_document_timeline for audit events.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"limit":       intSchema("max events (default 200, max 500)", 1, 500, 200),
		}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
				Limit      int    `json:"limit"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			limit := p.Limit
			if limit <= 0 {
				limit = 200
			}
			if limit > 500 {
				limit = 500
			}
			if _, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID}); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("document not found")
				}
				return nil, err
			}
			recipients, err := d.Queries.ListRecipientsByDocument(r.Context(), id)
			if err != nil {
				return nil, err
			}
			allResponded := true
			for _, rc := range recipients {
				if !recipientrules.HasTerminalResponse(rc.Status) {
					allResponded = false
					break
				}
			}
			if len(recipients) <= 1 && !allResponded {
				return map[string]any{"events": []any{}, "privacy_gated": true}, nil
			}
			rows, err := d.Queries.ListTelemetryByDocument(r.Context(), generated.ListTelemetryByDocumentParams{
				DocumentID: id,
				Limit:      int32(limit),
			})
			if err != nil {
				return nil, err
			}
			out := make([]map[string]any, 0, len(rows))
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
				out = append(out, entry)
			}
			return map[string]any{"events": out, "privacy_gated": false}, nil
		},
	})
}
