package handler

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/magictoken"
)

func TestComputeMagicTokenExpiry_NoDocExpiryCapsAt30Days(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	got := computeMagicTokenExpiry(&generated.Document{}, now)
	want := now.Add(magictoken.DefaultTTL)
	if !got.Valid || !got.Time.Equal(want) {
		t.Errorf("missing doc expiry should default to now+30d, got %v want %v", got.Time, want)
	}
}

func TestComputeMagicTokenExpiry_ClampsToDocExpiry(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	docExpiry := now.Add(7 * 24 * time.Hour) // shorter than 30 days
	doc := &generated.Document{ExpiresAt: pgtype.Timestamptz{Time: docExpiry, Valid: true}}
	got := computeMagicTokenExpiry(doc, now)
	if !got.Time.Equal(docExpiry) {
		t.Errorf("shorter doc expiry should win, got %v want %v", got.Time, docExpiry)
	}
}

func TestComputeMagicTokenExpiry_LongerDocExpiryDoesNotExtendDefault(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	docExpiry := now.Add(90 * 24 * time.Hour) // longer than 30 days
	doc := &generated.Document{ExpiresAt: pgtype.Timestamptz{Time: docExpiry, Valid: true}}
	got := computeMagicTokenExpiry(doc, now)
	want := now.Add(magictoken.DefaultTTL)
	if !got.Time.Equal(want) {
		t.Errorf("a long doc expiry must not push the token past 30d, got %v want %v", got.Time, want)
	}
}

func TestComputeMagicTokenExpiry_NilDocFallsBackToDefault(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	got := computeMagicTokenExpiry(nil, now)
	want := now.Add(magictoken.DefaultTTL)
	if !got.Valid || !got.Time.Equal(want) {
		t.Errorf("nil doc should fall back to default, got %v want %v", got.Time, want)
	}
}

func TestComputeMagicTokenExpiry_AlreadyExpiredDocBirthsExpiredToken(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	docExpiry := now.Add(-time.Hour)
	doc := &generated.Document{ExpiresAt: pgtype.Timestamptz{Time: docExpiry, Valid: true}}
	got := computeMagicTokenExpiry(doc, now)
	if !got.Time.Before(now) {
		t.Errorf("expired doc must not extend the token; got %v should be before %v", got.Time, now)
	}
}
