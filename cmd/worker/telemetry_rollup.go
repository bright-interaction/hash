// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"time"

	"github.com/bright-interaction/hash/internal/telemetry"
)

// Phase 8.3 telemetry rollup. Hourly: drain the rollup work queue (every
// document that still has unclaimed block.viewed rows), fold each document's
// unclaimed rows into its block-level dwell aggregate, then prune raw rows
// older than 90 days. Aggregate rows live forever so heatmaps keep working
// after the raw events expire; that holds because each raw row is claimed
// exactly once and accumulated, never recomputed from whatever rows happen to
// survive the prune (audit 2026-07-28 H1, migration 00041).
//
// Why a separate file: keeps the worker's main.go readable. The other
// three loops live alongside their helpers (reminders, expirations,
// webhooks); telemetry follows the same pattern. The tick body itself lives in
// internal/telemetry so the e2e suite can drive the real thing.

const (
	telemetryRollupInterval = 60 * time.Minute
	telemetryRetention      = 90 * 24 * time.Hour
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
	telemetry.RunRollupOnce(ctx, w.queries, telemetryRetention)
}
