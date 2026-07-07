package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/brightinteraction/hash/internal/compliance"
)

// Phase 12.2 compliance flag rollup. Nightly tick: fetch new EDPB feed
// items, walk each org's baseline + check whether any baseline doc
// mentions a topic the new item flags. Raised flags surface in the
// /compliance dashboard.
//
// Why nightly: EDPB advisories don't move faster than a day; running
// the keyword scan against every doc more often is wasted DB load.

const (
	complianceRollupInterval = 24 * time.Hour
	complianceLookback       = 14 * 24 * time.Hour // last two weeks of feed items considered
)

func (w *worker) loopComplianceRollup(ctx context.Context) {
	if w.complianceFlagger == nil || w.complianceFeed == nil {
		slog.Info("compliance rollup: flagger or feed not configured; loop disabled")
		return
	}
	tick := time.NewTicker(complianceRollupInterval)
	defer tick.Stop()
	w.runComplianceRollupOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runComplianceRollupOnce(ctx)
		}
	}
}

func (w *worker) runComplianceRollupOnce(ctx context.Context) {
	since := time.Now().Add(-complianceLookback)
	raised, err := compliance.FlagOnce(ctx, w.complianceFeed, w.complianceFlagger, since)
	if err != nil {
		slog.Warn("compliance rollup", "err", err)
		return
	}
	if raised > 0 {
		slog.Info("compliance rollup", "flags_raised", raised)
	}
}
