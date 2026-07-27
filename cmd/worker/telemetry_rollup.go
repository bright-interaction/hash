// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// Phase 8.3 telemetry rollup. Hourly: walk every document that received
// telemetry in the last 24h, upsert block-level dwell aggregates, then
// (best-effort) prune raw rows older than 90 days. Aggregate rows live
// forever so heatmaps keep working after the raw events expire.
//
// Why a separate file: keeps the worker's main.go readable. The other
// three loops live alongside their helpers (reminders, expirations,
// webhooks); telemetry follows the same pattern.

const (
	telemetryRollupInterval = 60 * time.Minute
	telemetryRetention      = 90 * 24 * time.Hour
	telemetryRollupWindow   = 25 * time.Hour // overlap by an hour so we never miss events near the boundary
)

func (w *worker) loopTelemetryRollup(ctx context.Context) {
	tick := time.NewTicker(telemetryRollupInterval)
	defer tick.Stop()
	w.runTelemetryRollupOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runTelemetryRollupOnce(ctx)
		}
	}
}

func (w *worker) runTelemetryRollupOnce(ctx context.Context) {
	cutoff := pgtype.Timestamptz{Time: time.Now().Add(-telemetryRollupWindow), Valid: true}
	docIDs, err := w.queries.ListDocumentsWithRecentTelemetry(ctx, cutoff)
	if err != nil {
		slog.Warn("telemetry: list recent docs", "err", err)
		return
	}
	for _, docID := range docIDs {
		rows, err := w.queries.AggregateBlockViews(ctx, docID)
		if err != nil {
			slog.Warn("telemetry: aggregate", "doc", docID, "err", err)
			continue
		}
		for _, row := range rows {
			if !row.BlockID.Valid {
				continue
			}
			avg := int32(0)
			if row.ViewCount > 0 {
				avg = int32(row.TotalDwellMs / int64(row.ViewCount))
			}
			last := row.LastEventAt
			lastTs, ok := last.(time.Time)
			if !ok {
				lastTs = time.Now()
			}
			if err := w.queries.UpsertEngagementSummary(ctx, generated.UpsertEngagementSummaryParams{
				DocumentID:   docID,
				BlockID:      row.BlockID.String,
				TotalViews:   row.ViewCount,
				TotalDwellMs: row.TotalDwellMs,
				AvgDwellMs:   avg,
				LastEventAt:  pgtype.Timestamptz{Time: lastTs, Valid: true},
			}); err != nil {
				slog.Warn("telemetry: upsert summary", "doc", docID, "block", row.BlockID.String, "err", err)
				continue
			}
		}
	}

	// Prune raw rows older than retention. Aggregate summary rows stay.
	pruneCutoff := pgtype.Timestamptz{Time: time.Now().Add(-telemetryRetention), Valid: true}
	n, err := w.queries.PruneTelemetryOlderThan(ctx, pruneCutoff)
	if err != nil {
		slog.Warn("telemetry: prune", "err", err)
		return
	}
	if n > 0 {
		slog.Info("telemetry: pruned raw events", "rows", n)
	}
}
