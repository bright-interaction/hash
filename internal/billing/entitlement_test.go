// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package billing

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func sub(status string, endOffset time.Duration, now time.Time) *generated.OrgSubscription {
	s := &generated.OrgSubscription{Status: status}
	if endOffset != 0 {
		s.CurrentPeriodStart = pgtype.Timestamptz{Time: now.Add(-30 * 24 * time.Hour), Valid: true}
		s.CurrentPeriodEnd = pgtype.Timestamptz{Time: now.Add(endOffset), Valid: true}
	}
	return s
}

func TestIsEntitled(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	day := 24 * time.Hour
	cases := []struct {
		name string
		s    *generated.OrgSubscription
		want bool
	}{
		{"nil", nil, false},
		{"active within period", sub("active", 5*day, now), true},
		{"active expired", sub("active", -1*day, now), false},
		{"active no period (unconfirmed)", sub("active", 0, now), false},
		{"trialing within period", sub("trialing", 5*day, now), true},
		{"incomplete (abandoned checkout)", sub("incomplete", 5*day, now), false},
		{"past_due", sub("past_due", 5*day, now), false},
		{"cancelled within period (cancel-at-period-end)", sub("cancelled", 5*day, now), true},
		{"cancelled after period", sub("cancelled", -1*day, now), false},
		{"unpaid", sub("unpaid", 5*day, now), false},
	}
	for _, c := range cases {
		if got := isEntitled(c.s, now); got != c.want {
			t.Errorf("%s: isEntitled = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestQuotaPeriod_EntitledUsesSubPeriod(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	s := sub("active", 5*24*time.Hour, now)
	start, end := quotaPeriod(s, now)
	if !start.Equal(s.CurrentPeriodStart.Time) || !end.Equal(s.CurrentPeriodEnd.Time) {
		t.Errorf("entitled sub should use its paid period, got [%v, %v]", start, end)
	}
}

func TestQuotaPeriod_FreeFallsBackToRolling30d(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	start, end := quotaPeriod(nil, now)
	if !end.Equal(now) || !start.Equal(now.AddDate(0, 0, -30)) {
		t.Errorf("no-sub org should get rolling 30d window, got [%v, %v]", start, end)
	}
	// A non-entitled sub also uses the rolling window, not its stale period.
	expired := sub("past_due", -1*24*time.Hour, now)
	s2, e2 := quotaPeriod(expired, now)
	if !e2.Equal(now) || !s2.Equal(now.AddDate(0, 0, -30)) {
		t.Errorf("non-entitled sub should get rolling 30d window, got [%v, %v]", s2, e2)
	}
}
