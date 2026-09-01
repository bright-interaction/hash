// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/timeline"
	"github.com/bright-interaction/hash/internal/versions"
)

// registerTimelineTools mounts the Phase 8.8 audit-timeline read surface
// for agents. Reads from the existing events table (no new captures);
// reuses Phase 8.1 versioning to embed inline diffs for document.updated
// entries.
func registerTimelineTools(s *Server, d Deps) {
	s.RegisterTool(ToolDef{
		Name:        "get_document_timeline",
		Description: "Return the audit-event timeline for a document: sends, opens, signs, declines, voids, expirations, reminders, webhook dispatches, MCP writes. Consecutive same-actor + same-kind events within 5 minutes collapse into a single entry with occurrences > 1. Pass diff=true to embed Phase 8.1 block-level diffs inline for document.updated entries.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"kinds": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "optional kind filter, e.g. ['document.sent','document.signed']",
			},
			"since": stringSchema("optional RFC3339 lower bound"),
			"until": stringSchema("optional RFC3339 upper bound"),
			"limit": intSchema("max entries before grouping (default 200, max 1000)", 1, 1000, 200),
			"group": map[string]any{
				"type":        "boolean",
				"description": "collapse consecutive same-actor same-kind events within 5 min (default true)",
			},
			"diff": map[string]any{
				"type":        "boolean",
				"description": "embed Phase 8.1 block-level diff for document.updated entries (default false; small extra DB cost)",
			},
		}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string   `json:"document_id"`
				Kinds      []string `json:"kinds"`
				Since      string   `json:"since"`
				Until      string   `json:"until"`
				Limit      int      `json:"limit"`
				Group      *bool    `json:"group"`
				Diff       bool     `json:"diff"`
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
			limit := p.Limit
			if limit <= 0 {
				limit = 200
			}
			if limit > 1000 {
				limit = 1000
			}
			since := parseRFC3339(p.Since)
			until := parseRFC3339(p.Until)
			rows, err := d.Queries.ListEventsByDocumentFiltered(r.Context(), generated.ListEventsByDocumentFilteredParams{
				DocumentID: pgtype.UUID{Bytes: id, Valid: true},
				Column2:    p.Kinds,
				Column3:    tsParam(since),
				Column4:    tsParam(until),
				Limit:      int32(limit),
			})
			if err != nil {
				return nil, err
			}
			entries := make([]timeline.Entry, 0, len(rows))
			for _, ev := range rows {
				entries = append(entries, timeline.FromEvent(ev))
			}
			group := true
			if p.Group != nil {
				group = *p.Group
			}
			if group {
				entries = timeline.Group(entries)
			}
			if p.Diff && d.Versions != nil {
				entries, _ = timeline.AttachDiffs(entries, mcpDiffLookup(r.Context(), d.Versions, u.OrgID))
			}
			entries, _ = timeline.AttachActorEmails(entries, mcpActorEmailLookup(r.Context(), d.Queries, u.OrgID))
			return map[string]any{"entries": entries, "count": len(entries)}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "get_org_activity",
		Description: "Return the org-wide activity feed (every audit event across every document the caller can access). Supports kind + actor + document + since/until filters. Use this to spot anomalies (e.g. a single user generating an unusual burst of voids).",
		InputSchema: schemaObject(map[string]any{
			"kinds": map[string]any{
				"type":  "array",
				"items": map[string]any{"type": "string"},
			},
			"actor_user_id": stringSchema("optional actor uuid filter"),
			"document_id":   stringSchema("optional document uuid filter"),
			"since":         stringSchema("optional RFC3339 lower bound"),
			"until":         stringSchema("optional RFC3339 upper bound"),
			"limit":         intSchema("max entries (default 200, max 1000)", 1, 1000, 200),
		}, nil),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				Kinds       []string `json:"kinds"`
				ActorUserID string   `json:"actor_user_id"`
				DocumentID  string   `json:"document_id"`
				Since       string   `json:"since"`
				Until       string   `json:"until"`
				Limit       int      `json:"limit"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			limit := int32(p.Limit)
			if limit <= 0 {
				limit = 200
			}
			if limit > 1000 {
				limit = 1000
			}
			actor := uuid.Nil
			if p.ActorUserID != "" {
				if id, err := uuid.Parse(p.ActorUserID); err == nil {
					actor = id
				}
			}
			docID := uuid.Nil
			if p.DocumentID != "" {
				if id, err := uuid.Parse(p.DocumentID); err == nil {
					docID = id
				}
			}
			rows, err := d.Queries.ListOrgActivityFiltered(r.Context(), generated.ListOrgActivityFilteredParams{
				OrgID:   u.OrgID,
				Column2: p.Kinds,
				Column3: actor,
				Column4: docID,
				Column5: tsParam(parseRFC3339(p.Since)),
				Column6: tsParam(parseRFC3339(p.Until)),
				Limit:   limit,
			})
			if err != nil {
				return nil, err
			}
			entries := make([]timeline.Entry, 0, len(rows))
			for _, ev := range rows {
				entries = append(entries, timeline.FromEvent(ev))
			}
			entries, _ = timeline.AttachActorEmails(entries, mcpActorEmailLookup(r.Context(), d.Queries, u.OrgID))
			return map[string]any{"entries": entries, "count": len(entries)}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "get_org_activity_leaderboard",
		Description: "Return the top actors by event count over the last N days (default 7). Useful for spotting unusual activity bursts.",
		InputSchema: schemaObject(map[string]any{
			"days":  intSchema("lookback window in days (default 7, max 365)", 1, 365, 7),
			"limit": intSchema("max actors (default 10, max 100)", 1, 100, 10),
		}, nil),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				Days  int `json:"days"`
				Limit int `json:"limit"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			if p.Days <= 0 {
				p.Days = 7
			}
			if p.Limit <= 0 {
				p.Limit = 10
			}
			since := time.Now().Add(-time.Duration(p.Days) * 24 * time.Hour)
			rows, err := d.Queries.OrgActivityActorLeaderboard(r.Context(), generated.OrgActivityActorLeaderboardParams{
				OrgID:     u.OrgID,
				CreatedAt: pgtype.Timestamptz{Time: since, Valid: true},
				Limit:     int32(p.Limit),
			})
			if err != nil {
				return nil, err
			}
			lookup := mcpActorEmailLookup(r.Context(), d.Queries, u.OrgID)
			ids := make([]string, 0, len(rows))
			for _, row := range rows {
				if row.ActorUserID.Valid {
					ids = append(ids, uuid.UUID(row.ActorUserID.Bytes).String())
				}
			}
			emails, _ := lookup(ids)
			out := make([]map[string]any, 0, len(rows))
			for _, row := range rows {
				if !row.ActorUserID.Valid {
					continue
				}
				id := uuid.UUID(row.ActorUserID.Bytes).String()
				out = append(out, map[string]any{
					"actor_user_id": id,
					"actor_email":   emails[id],
					"event_count":   row.EventCount,
				})
			}
			return map[string]any{"entries": out, "days": p.Days}, nil
		},
	})
}

func parseRFC3339(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

func tsParam(t *time.Time) pgtype.Timestamptz {
	if t == nil || t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

func mcpDiffLookup(ctx context.Context, ve *versions.Engine, orgID uuid.UUID) timeline.VersionDiffLookup {
	_ = orgID
	return func(docID string, eventTime time.Time) (any, bool, error) {
		id, err := uuid.Parse(docID)
		if err != nil {
			return nil, false, nil
		}
		rows, err := ve.History(ctx, id, 100)
		if err != nil {
			return nil, false, err
		}
		target := latestVersionAtOrBefore(rows, eventTime)
		if target == nil || target.VersionNo <= 1 {
			return nil, false, nil
		}
		prior, err := ve.GetByNo(ctx, id, target.VersionNo-1)
		if err != nil {
			return nil, false, nil
		}
		changes, err := versions.Diff(prior.BlockTreeJson, target.BlockTreeJson)
		if err != nil {
			return nil, false, nil
		}
		return changes, true, nil
	}
}

// latestVersionAtOrBefore matches the actual authoring order: persist the
// document, snapshot its new version, then append the audit event. History is
// returned newest-first, so the first snapshot not later than the event is the
// version produced by that edit. Sub-second event timestamps are preserved by
// timeline.FromEvent to disambiguate rapid create/edit sequences.
func latestVersionAtOrBefore(rows []*generated.DocumentVersion, eventTime time.Time) *generated.DocumentVersion {
	for _, row := range rows {
		if row == nil || !row.CreatedAt.Valid || row.CreatedAt.Time.After(eventTime) {
			continue
		}
		return row
	}
	return nil
}

func mcpActorEmailLookup(ctx context.Context, q *generated.Queries, orgID uuid.UUID) timeline.ActorEmailLookup {
	return func(actorIDs []string) (map[string]string, error) {
		out := map[string]string{}
		for _, raw := range actorIDs {
			id, err := uuid.Parse(raw)
			if err != nil {
				continue
			}
			u, err := q.GetUser(ctx, id)
			if err != nil {
				continue
			}
			if u.OrgID == orgID {
				out[raw] = u.Email
			}
		}
		return out, nil
	}
}
