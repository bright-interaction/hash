// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/compliance"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// zeroTime is the lower-bound passed to feed Fetch when we want every
// item. Used by the on-demand flag-run endpoint.
func zeroTime() time.Time { return time.Time{} }

// Phase 12 REST surface. Seed the baseline kit, list flags, transition
// flag status, fetch the baseline row.

// POST /api/v1/compliance/seed
//
// Body: { "business_type": "law_firm" | "saas" | ..., "jurisdiction": "SE" }
func (s *Server) handleSeedCompliance(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if s.Compliance == nil {
		writeError(w, http.StatusServiceUnavailable, "compliance seeder not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var in struct {
		BusinessType string `json:"business_type"`
		Jurisdiction string `json:"jurisdiction"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	bt := compliance.BusinessType(in.BusinessType)
	if !bt.Valid() {
		writeError(w, http.StatusBadRequest, "business_type must be law_firm | saas | consulting | healthcare | fintech | other")
		return
	}
	res, err := s.Compliance.Seed(r.Context(), compliance.SeedInput{
		OrgID:        sess.OrgID,
		UserID:       sess.UserID,
		BusinessType: bt,
		Jurisdiction: in.Jurisdiction,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID:       sess.OrgID,
		ActorUserID: &sess.UserID,
		Kind:        "compliance.baseline_seeded",
		IP:          firstIPFromHeader(r),
		UserAgent:   r.UserAgent(),
		Payload: map[string]any{
			"business_type":      bt,
			"jurisdiction":       in.Jurisdiction,
			"eidas_rules_seeded": res.EIDASRulesSeeded,
		},
	})
	writeJSON(w, http.StatusOK, res)
}

// GET /api/v1/compliance/baseline
func (s *Server) handleGetComplianceBaseline(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	row, err := s.Queries.GetComplianceBaseline(r.Context(), sess.OrgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusOK, map[string]any{"baseline": nil})
			return
		}
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"baseline": baselineToDTO(row)})
}

// GET /api/v1/compliance/flags?status=open
func (s *Server) handleListComplianceFlags(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	status := r.URL.Query().Get("status")
	rows, err := s.Queries.ListComplianceFlags(r.Context(), generated.ListComplianceFlagsParams{
		OrgID:   sess.OrgID,
		Column2: status,
		Limit:   500,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, f := range rows {
		out = append(out, flagToDTO(f))
	}
	writeJSON(w, http.StatusOK, map[string]any{"flags": out, "count": len(out)})
}

// PATCH /api/v1/compliance/flags/{id}
//
// Body: { "status": "acknowledged" | "resolved" | "dismissed" | "open" }
func (s *Server) handleSetComplianceFlagStatus(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	idRaw := chiURLParam(r, "id")
	id, err := uuid.Parse(idRaw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var in struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	switch in.Status {
	case "open", "acknowledged", "resolved", "dismissed":
	default:
		writeError(w, http.StatusBadRequest, "status must be open|acknowledged|resolved|dismissed")
		return
	}
	row, err := s.Queries.SetComplianceFlagStatus(r.Context(), generated.SetComplianceFlagStatusParams{
		ID:     id,
		OrgID:  sess.OrgID,
		Status: in.Status,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, flagToDTO(row))
}

// POST /api/v1/compliance/flag-run
//
// Manual trigger for the EDPB-flag sweep. Useful for demo + for
// admins who want to refresh without waiting for the worker tick.
func (s *Server) handleComplianceFlagRun(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	_ = sess
	if s.ComplianceFlagger == nil || s.ComplianceFeed == nil {
		writeError(w, http.StatusServiceUnavailable, "flagger not configured")
		return
	}
	items, err := s.ComplianceFeed.Fetch(r.Context(), zeroTime())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if len(items) == 0 {
		items = compliance.SampleFeedItems() // seed the dashboard with starter items if the feed has nothing
	}
	raised, err := s.ComplianceFlagger.FlagRun(r.Context(), items)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items_processed": len(items), "flags_raised": raised})
}

func baselineToDTO(b *generated.ComplianceBaseline) map[string]any {
	out := map[string]any{
		"org_id":         b.OrgID.String(),
		"business_type":  b.BusinessType,
		"jurisdiction":   b.Jurisdiction,
		"schema_version": b.SchemaVersion,
		"seeded_at":      b.SeededAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		"updated_at":     b.UpdatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if b.DpaTemplateID.Valid {
		out["dpa_template_id"] = uuid.UUID(b.DpaTemplateID.Bytes).String()
	}
	if b.RecordsDocID.Valid {
		out["records_doc_id"] = uuid.UUID(b.RecordsDocID.Bytes).String()
	}
	if b.PrivacyNoticeID.Valid {
		out["privacy_notice_id"] = uuid.UUID(b.PrivacyNoticeID.Bytes).String()
	}
	return out
}

func flagToDTO(f *generated.ComplianceFlag) map[string]any {
	out := map[string]any{
		"id":               f.ID.String(),
		"org_id":           f.OrgID.String(),
		"update_ref":       f.UpdateRef,
		"update_title":     f.UpdateTitle,
		"affected_topic":   f.AffectedTopic,
		"block_id":         f.BlockID,
		"severity":         f.Severity,
		"suggested_action": f.SuggestedAction,
		"status":           f.Status,
		"raised_at":        f.RaisedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if f.DocumentID.Valid {
		out["document_id"] = uuid.UUID(f.DocumentID.Bytes).String()
	}
	if f.TemplateID.Valid {
		out["template_id"] = uuid.UUID(f.TemplateID.Bytes).String()
	}
	if f.ResolvedAt.Valid {
		out["resolved_at"] = f.ResolvedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return out
}
