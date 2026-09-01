// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package telemetry holds the engagement rollup tick. It lives here rather
// than in package main so the e2e suite can drive the real tick against a real
// Postgres instead of asserting against a copy of it (audit 2026-07-28 H1: the
// round-1 fix for this bug shipped a regression test that no CI job executed).
package telemetry

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// RollupQueries is the slice of *generated.Queries the tick needs.
type RollupQueries interface {
	ListDocumentsWithPendingRollup(ctx context.Context) ([]uuid.UUID, error)
	RollupBlockViews(ctx context.Context, documentID uuid.UUID) (int64, error)
	PruneTelemetryOlderThan(ctx context.Context, createdAt pgtype.Timestamptz) (*generated.PruneTelemetryOlderThanRow, error)
	PruneEngagementOlderThan(ctx context.Context, lastEventAt pgtype.Timestamptz) (int64, error)
}

// RunRollupOnce drains the rollup work queue and then enforces the raw-event
// retention TTL.
//
// Ordering matters and is load-bearing: rollup first, prune second. Events
// that reached the 90-day edge while the worker was down are folded into the
// summary on the way out instead of being deleted uncounted. Summary rows
// whose newest contributing event is also past the edge are then removed so
// optional analytics cannot form a permanent recipient reading profile.
//
// Each block.viewed row is claimed exactly once by RollupBlockViews (see
// migration 00041), so the per-block totals do not double count or partially
// decay while the summary remains inside its bounded window. Once the newest
// contributing event reaches the retention edge, the whole summary is pruned.
func RunRollupOnce(ctx context.Context, q RollupQueries, retention time.Duration) {
	docIDs, err := q.ListDocumentsWithPendingRollup(ctx)
	if err != nil {
		// Fail closed: the listing failing means the database is not
		// answering, so pruning now would delete rows we cannot prove were
		// counted. The next tick retries in an hour.
		slog.Warn("telemetry: list pending rollup", "err", err)
		return
	}
	for _, docID := range docIDs {
		if _, err := q.RollupBlockViews(ctx, docID); err != nil {
			// The claim and the summary write share one statement, so a
			// failure here rolls back the claim too: nothing is lost, the
			// rows stay pending and the next tick retries them.
			slog.Warn("telemetry: rollup block views", "doc", docID, "err", err)
			continue
		}
	}

	// Prune raw rows past retention. Aggregate rows follow the same cutoff. The
	// prune is deliberately NOT skipped when an individual document failed
	// above: the 90-day TTL is a privacy commitment (migration 00011) and must
	// not be held hostage to an aggregation bug. Loss is made loud instead.
	pruneCutoff := pgtype.Timestamptz{Time: time.Now().Add(-retention), Valid: true}
	pruned, err := q.PruneTelemetryOlderThan(ctx, pruneCutoff)
	if err != nil {
		slog.Warn("telemetry: prune", "err", err)
		return
	}
	if pruned != nil && pruned.DeletedRows > 0 {
		slog.Info("telemetry: pruned raw events", "rows", pruned.DeletedRows)
	}
	if pruned != nil && pruned.UnrolledViews > 0 {
		slog.Error("telemetry: block.viewed events hit the retention edge before they were rolled up, engagement totals under-count by this many views",
			"views", pruned.UnrolledViews)
	}
	prunedSummaries, err := q.PruneEngagementOlderThan(ctx, pruneCutoff)
	if err != nil {
		slog.Warn("telemetry: prune engagement summaries", "err", err)
		return
	}
	if prunedSummaries > 0 {
		slog.Info("telemetry: pruned engagement summaries", "rows", prunedSummaries)
	}
}
