// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/http"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// Phase 10.1: aggregate org-wide insights. Composes the existing
// dashboard counts + completion KPI + time-to-sign p50 + agent-vs-human
// authoring split + top engaged blocks across the org. Read-only, no
// new captures; the underlying data lands via Phase 8.3 telemetry +
// audit events already captured.

// GET /api/v1/insights
func (s *Server) handleOrgInsights(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	counts, err := s.Queries.OrgInsightsCounts(r.Context(), sess.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	completion, err := s.Queries.OrgInsightsCompletionRecent(r.Context(), sess.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	tts, err := s.Queries.OrgInsightsTimeToSign(r.Context(), sess.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	authoring, err := s.Queries.OrgInsightsAgentAuthored(r.Context(), sess.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	top, err := s.Queries.OrgInsightsTopEngagedBlocks(r.Context(), generated.OrgInsightsTopEngagedBlocksParams{
		OrgID: sess.OrgID,
		Limit: 10,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	engagement := make([]map[string]any, 0, len(top))
	for _, r := range top {
		engagement = append(engagement, map[string]any{
			"document_id":    r.DocumentID.String(),
			"block_id":       r.BlockID,
			"total_views":    r.TotalViews,
			"total_dwell_ms": r.TotalDwellMs,
			"avg_dwell_ms":   r.AvgDwellMs,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"by_status": map[string]int32{
			"draft":       counts.DraftCount,
			"sent":        counts.SentCount,
			"in_progress": counts.InProgressCount,
			"completed":   counts.CompletedCount,
			"declined":    counts.DeclinedCount,
			"voided":      counts.VoidedCount,
			"expired":     counts.ExpiredCount,
		},
		"total_documents":      counts.TotalCount,
		"completed_30d":        completion,
		"time_to_sign_p50_sec": tts,
		"authoring": map[string]int32{
			"agent_30d": authoring.AgentCount,
			"human_30d": authoring.HumanCount,
		},
		"top_engaged_blocks": engagement,
	})
}
