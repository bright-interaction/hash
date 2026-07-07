package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// Soft-delete purge loop (carryover from audit fix #10).
//
// fix #10 changed DeleteDraftDocument from a hard DROP to flipping
// documents.deleted_at, plus added a PurgeSoftDeletedDocuments query
// that takes a cutoff timestamp. This loop is the cron that actually
// runs the purge so the grace window doesn't grow without bound.
//
// Cadence: every 6 hours. Cutoff: 90 days after deleted_at, matching
// the privacy-policy retention statement for in-flight DSR requests.
//
// Per-tick budget is bounded because PurgeSoftDeletedDocuments is a
// single targeted DELETE; if production ever accumulates more than a
// few thousand soft-deleted docs the loop will need batching, but
// for the current load the one-shot DELETE is fine.

const (
	softDeletePurgeInterval = 6 * time.Hour
	softDeleteGraceWindow   = 90 * 24 * time.Hour
)

func (w *worker) loopSoftDeletePurge(ctx context.Context) {
	tick := time.NewTicker(softDeletePurgeInterval)
	defer tick.Stop()
	w.runSoftDeletePurgeOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runSoftDeletePurgeOnce(ctx)
		}
	}
}

func (w *worker) runSoftDeletePurgeOnce(ctx context.Context) {
	cutoff := pgtype.Timestamptz{Time: time.Now().Add(-softDeleteGraceWindow), Valid: true}
	if err := w.queries.PurgeSoftDeletedDocuments(ctx, cutoff); err != nil {
		slog.Warn("soft_delete_purge: purge failed", "err", err, "cutoff", cutoff.Time)
		return
	}
	slog.Debug("soft_delete_purge: tick complete", "cutoff", cutoff.Time)
}
