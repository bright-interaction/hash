// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestLatestVersionAtOrBeforeAuditEvent(t *testing.T) {
	base := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	version := func(no int32, at time.Time) *generated.DocumentVersion {
		return &generated.DocumentVersion{
			VersionNo: no,
			CreatedAt: pgtype.Timestamptz{Time: at, Valid: true},
		}
	}
	rows := []*generated.DocumentVersion{
		version(3, base.Add(900*time.Microsecond)),
		version(2, base.Add(500*time.Microsecond)),
		version(1, base.Add(100*time.Microsecond)),
	}
	got := latestVersionAtOrBefore(rows, base.Add(600*time.Microsecond))
	if got == nil || got.VersionNo != 2 {
		t.Fatalf("got %+v, want version 2", got)
	}
}

func TestLatestVersionAtOrBeforeRejectsFutureOnlyRows(t *testing.T) {
	base := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	rows := []*generated.DocumentVersion{{
		VersionNo: 1,
		CreatedAt: pgtype.Timestamptz{Time: base.Add(time.Microsecond), Valid: true},
	}}
	if got := latestVersionAtOrBefore(rows, base); got != nil {
		t.Fatalf("got future version %+v", got)
	}
}
