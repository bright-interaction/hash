package sign

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/db/generated"
)

func ts(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }

func TestCheckMagicLinkExpiry(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	cases := []struct {
		name    string
		rowExp  pgtype.Timestamptz
		docExp  pgtype.Timestamptz
		wantErr error
	}{
		{"both null is always valid", pgtype.Timestamptz{}, pgtype.Timestamptz{}, nil},
		{"row expiry in past expires the link", ts(past), pgtype.Timestamptz{}, ErrMagicLinkExpired},
		{"doc expiry in past expires the link", pgtype.Timestamptz{}, ts(past), ErrMagicLinkExpired},
		{"row expiry in future is valid", ts(future), pgtype.Timestamptz{}, nil},
		{"doc expiry in future is valid", pgtype.Timestamptz{}, ts(future), nil},
		{"both in future is valid", ts(future), ts(future), nil},
		{"row expired, doc fine still expires", ts(past), ts(future), ErrMagicLinkExpired},
		{"doc expired, row fine still expires", ts(future), ts(past), ErrMagicLinkExpired},
		{"row expiry exactly now is still valid (after, not at)", ts(now), pgtype.Timestamptz{}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := &generated.GetRecipientByTokenHashRow{MagicTokenExpiresAt: tc.rowExp}
			doc := &generated.Document{ExpiresAt: tc.docExp}
			got := checkMagicLinkExpiry(row, doc, now)
			if !errors.Is(got, tc.wantErr) {
				t.Errorf("got %v, want %v", got, tc.wantErr)
			}
		})
	}
}

func TestCheckMagicLinkExpiry_NilGuards(t *testing.T) {
	if err := checkMagicLinkExpiry(nil, nil, time.Now()); err != nil {
		t.Errorf("nil inputs should be a no-op, got %v", err)
	}
}

func TestEngineNow_DefaultsToTimeNow(t *testing.T) {
	e := &Engine{}
	before := time.Now()
	got := e.now()
	after := time.Now()
	if got.Before(before) || got.After(after.Add(time.Second)) {
		t.Errorf("Engine.now() should fall back to time.Now(), got %v", got)
	}
}

func TestEngineNow_RespectsInjectedClock(t *testing.T) {
	fixed := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	e := &Engine{Now: func() time.Time { return fixed }}
	if got := e.now(); !got.Equal(fixed) {
		t.Errorf("Engine.Now override ignored: got %v, want %v", got, fixed)
	}
}
