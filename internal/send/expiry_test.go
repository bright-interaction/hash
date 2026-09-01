// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestValidateExpiryForSendRequiresAdmissionLead(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	for _, expiresAt := range []pgtype.Timestamptz{
		{Time: now.Add(-time.Second), Valid: true},
		{Time: now.Add(MinimumExpiryLead), Valid: true},
	} {
		if err := ValidateExpiryForSend(expiresAt, now); !errors.Is(err, ErrExpiryTooSoon) {
			t.Fatalf("expiry %s: got %v, want ErrExpiryTooSoon", expiresAt.Time, err)
		}
	}
	if err := ValidateExpiryForSend(pgtype.Timestamptz{}, now); err != nil {
		t.Fatalf("optional expiry rejected: %v", err)
	}
	if err := ValidateExpiryForSend(pgtype.Timestamptz{
		Time: now.Add(MinimumExpiryLead + time.Second), Valid: true,
	}, now); err != nil {
		t.Fatalf("fresh expiry rejected: %v", err)
	}
}
