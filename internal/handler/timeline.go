package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/timeline"
	"github.com/brightinteraction/hash/internal/versions"
)

// Phase 8.8 timeline surface. The audit-event timeline lives at
// /api/v1/documents/{id}/timeline (the path 8.3 used for telemetry has
// moved to /telemetry-stream so this one is reserved for the human-
// facing "what happened to this document" view).

const defaultTimelineLimit = 200
const maxTimelineLimit = 1000

// GET /api/v1/documents/{id}/timeline?kinds=document.sent,document.signed&since=...&until=...&group=true&diff=true&limit=200
func (s *Server) handleAuditTimeline(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
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
	filter := parseTimelineFilter(r)
	entries, err := s.fetchDocTimeline(r.Context(), docID, filter)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if r.URL.Query().Get("group") != "false" {
		entries = timeline.Group(entries)
	}
	if r.URL.Query().Get("diff") == "true" && s.Versions != nil {
		entries, _ = timeline.AttachDiffs(entries, s.versionDiffLookupFor(r.Context(), sess.OrgID))
	}
	if r.URL.Query().Get("emails") != "false" {
		entries, _ = timeline.AttachActorEmails(entries, s.actorEmailLookup(r.Context(), sess.OrgID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "count": len(entries)})
}

// GET /api/v1/documents/{id}/timeline.csv
func (s *Server) handleAuditTimelineCSV(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
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
	filter := parseTimelineFilter(r)
	filter.Limit = maxTimelineLimit
	entries, err := s.fetchDocTimeline(r.Context(), docID, filter)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	entries, _ = timeline.AttachActorEmails(entries, s.actorEmailLookup(r.Context(), sess.OrgID))

	filename := fmt.Sprintf("hash-timeline-%s.csv", doc.ID.String())
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	if err := timeline.ExportCSV(w, entries); err != nil {
		// Headers already flushed; nothing more we can do but log.
		return
	}
}

// GET /api/v1/activity?kinds=&actor_user_id=&document_id=&since=&until=&limit=
//
// Org-wide activity feed. Same shape as the per-doc timeline.
func (s *Server) handleOrgActivity(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	filter := parseTimelineFilter(r)
	actorID := parseOptionalRawUUID(r.URL.Query().Get("actor_user_id"))
	docID := parseOptionalRawUUID(r.URL.Query().Get("document_id"))

	rows, err := s.Queries.ListOrgActivityFiltered(r.Context(), generated.ListOrgActivityFilteredParams{
		OrgID:   sess.OrgID,
		Column2: filter.Kinds,
		Column3: actorID,
		Column4: docID,
		Column5: timestampParam(filter.Since),
		Column6: timestampParam(filter.Until),
		Limit:   filter.LimitOrDefault(defaultTimelineLimit),
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	entries := make([]timeline.Entry, 0, len(rows))
	for _, ev := range rows {
		entries = append(entries, timeline.FromEvent(ev))
	}
	entries, _ = timeline.AttachActorEmails(entries, s.actorEmailLookup(r.Context(), sess.OrgID))
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "count": len(entries)})
}

// GET /api/v1/activity/leaderboard?days=7&limit=10
func (s *Server) handleOrgActivityLeaderboard(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	days := parseIntDefault(r.URL.Query().Get("days"), 7, 1, 365)
	limit := parseIntDefault(r.URL.Query().Get("limit"), 10, 1, 100)
	since := time.Now().Add(-time.Duration(days) * 24 * time.Hour)

	rows, err := s.Queries.OrgActivityActorLeaderboard(r.Context(), generated.OrgActivityActorLeaderboardParams{
		OrgID:     sess.OrgID,
		CreatedAt: pgtype.Timestamptz{Time: since, Valid: true},
		Limit:     int32(limit),
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	lookupEmails := s.actorEmailLookup(r.Context(), sess.OrgID)
	type entry struct {
		ActorUserID string `json:"actor_user_id"`
		ActorEmail  string `json:"actor_email,omitempty"`
		EventCount  int32  `json:"event_count"`
	}
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.ActorUserID.Valid {
			ids = append(ids, uuid.UUID(row.ActorUserID.Bytes).String())
		}
	}
	emails, _ := lookupEmails(ids)
	out := make([]entry, 0, len(rows))
	for _, row := range rows {
		if !row.ActorUserID.Valid {
			continue
		}
		id := uuid.UUID(row.ActorUserID.Bytes).String()
		out = append(out, entry{
			ActorUserID: id,
			ActorEmail:  emails[id],
			EventCount:  row.EventCount,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": out,
		"days":    days,
	})
}

// fetchDocTimeline runs the filtered query + converts rows to Entry.
func (s *Server) fetchDocTimeline(ctx context.Context, docID uuid.UUID, filter timelineFilter) ([]timeline.Entry, error) {
	rows, err := s.Queries.ListEventsByDocumentFiltered(ctx, generated.ListEventsByDocumentFilteredParams{
		DocumentID: pgtype.UUID{Bytes: docID, Valid: true},
		Column2:    filter.Kinds,
		Column3:    timestampParam(filter.Since),
		Column4:    timestampParam(filter.Until),
		Limit:      filter.LimitOrDefault(defaultTimelineLimit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]timeline.Entry, 0, len(rows))
	for _, ev := range rows {
		out = append(out, timeline.FromEvent(ev))
	}
	return out, nil
}

// timelineFilter mirrors timeline.Filter but parses cleanly from a chi
// request without leaking pgtype into the package boundary.
type timelineFilter struct {
	Kinds []string
	Since *time.Time
	Until *time.Time
	Limit int32
}

func (f timelineFilter) LimitOrDefault(def int32) int32 {
	if f.Limit <= 0 {
		return def
	}
	if f.Limit > maxTimelineLimit {
		return maxTimelineLimit
	}
	return f.Limit
}

func parseTimelineFilter(r *http.Request) timelineFilter {
	q := r.URL.Query()
	f := timelineFilter{}
	if raw := q.Get("kinds"); raw != "" {
		for _, k := range strings.Split(raw, ",") {
			k = strings.TrimSpace(k)
			if k != "" {
				f.Kinds = append(f.Kinds, k)
			}
		}
	}
	if raw := q.Get("since"); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			f.Since = &t
		}
	}
	if raw := q.Get("until"); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			f.Until = &t
		}
	}
	if raw := q.Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			f.Limit = int32(n)
		}
	}
	return f
}

func timestampParam(t *time.Time) pgtype.Timestamptz {
	if t == nil || t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

func parseOptionalUUID(raw string) pgtype.UUID {
	if raw == "" {
		return pgtype.UUID{}
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: id, Valid: true}
}

// parseOptionalRawUUID returns uuid.Nil for empty / malformed input.
// The matching SQL uses `$N = '00000000-...' OR col = $N` so the all-
// zeros UUID acts as the "no filter" sentinel.
func parseOptionalRawUUID(raw string) uuid.UUID {
	if raw == "" {
		return uuid.Nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil
	}
	return id
}

func parseIntDefault(raw string, def, minV, maxV int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if n < minV {
		return minV
	}
	if n > maxV {
		return maxV
	}
	return n
}

// versionDiffLookupFor returns a closure timeline.AttachDiffs uses to
// resolve the diff between an edited-version and its predecessor.
func (s *Server) versionDiffLookupFor(ctx context.Context, orgID uuid.UUID) timeline.VersionDiffLookup {
	return func(docID string, eventTime time.Time) (any, bool, error) {
		id, err := uuid.Parse(docID)
		if err != nil {
			return nil, false, nil
		}
		// Find the version snapshotted at-or-just-after eventTime. The
		// versions table is monotonic (version_no increments per doc),
		// so we walk the history and pick the first row whose
		// CreatedAt >= eventTime.
		rows, err := s.Versions.History(ctx, id, 100)
		if err != nil {
			return nil, false, err
		}
		// rows are newest-first; reverse-scan to find the smallest one
		// >= eventTime
		var target *generated.DocumentVersion
		for i := len(rows) - 1; i >= 0; i-- {
			if rows[i].CreatedAt.Time.Before(eventTime) {
				continue
			}
			target = rows[i]
			break
		}
		if target == nil || target.VersionNo <= 1 {
			return nil, false, nil
		}
		prior, err := s.Versions.GetByNo(ctx, id, target.VersionNo-1)
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

// actorEmailLookup returns a closure that resolves user IDs to email
// addresses in a single query.
func (s *Server) actorEmailLookup(ctx context.Context, orgID uuid.UUID) timeline.ActorEmailLookup {
	return func(actorIDs []string) (map[string]string, error) {
		out := map[string]string{}
		for _, raw := range actorIDs {
			id, err := uuid.Parse(raw)
			if err != nil {
				continue
			}
			u, err := s.Queries.GetUser(ctx, id)
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

// guard imports
var _ = chi.URLParam
