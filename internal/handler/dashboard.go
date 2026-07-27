// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// handleDashboard returns the KPI block the sender app's home page renders.
// All metrics are org-scoped, computed on the fly (no caching for v1; the
// queries are cheap and the data set is small per-org).
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	ctx := r.Context()

	statusRows, _ := s.Queries.CountDocumentsByStatus(ctx, u.OrgID)
	byStatus := make(map[string]int64, len(statusRows))
	for _, r := range statusRows {
		byStatus[r.Status] = r.N
	}

	since24h := pgtype.Timestamptz{Time: time.Now().Add(-24 * time.Hour), Valid: true}
	sentToday, _ := s.Queries.CountSentSince(ctx, generated.CountSentSinceParams{OrgID: u.OrgID, SentAt: since24h})
	completed30d, _ := s.Queries.CountCompletedSince(ctx, generated.CountCompletedSinceParams{
		OrgID:       u.OrgID,
		CompletedAt: pgtype.Timestamptz{Time: time.Now().Add(-30 * 24 * time.Hour), Valid: true},
	})
	awaiting, _ := s.Queries.CountAwaitingSig(ctx, u.OrgID)
	expiring, _ := s.Queries.CountExpiringSoon(ctx, u.OrgID)
	timeToSign, _ := s.Queries.TimeToSignP50Seconds(ctx, u.OrgID)
	split, _ := s.Queries.AgentVsHumanDocumentSplit(ctx, u.OrgID)

	out := map[string]any{
		"by_status":            byStatus,
		"sent_24h":             sentToday,
		"completed_30d":        completed30d,
		"awaiting_signature":   awaiting,
		"expiring_within_7d":   expiring,
		"time_to_sign_p50_sec": timeToSign,
		"agent_authored_30d":   split.Agent,
		"human_authored_30d":   split.Human,
	}
	writeJSON(w, http.StatusOK, out)
}
