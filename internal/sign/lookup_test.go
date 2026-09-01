// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
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

func TestCheckActiveCeremonyAccess(t *testing.T) {
	for _, status := range []string{"sent", "in_progress", "changes_requested"} {
		t.Run(status+" is active", func(t *testing.T) {
			if err := checkActiveCeremonyAccess(&generated.Document{Status: status}); err != nil {
				t.Fatalf("active ceremony rejected: %v", err)
			}
		})
	}
	for _, status := range []string{"", "draft", "completed", "voided", "declined", "expired"} {
		t.Run(status+" is rejected", func(t *testing.T) {
			if err := checkActiveCeremonyAccess(&generated.Document{Status: status}); !errors.Is(err, ErrDocumentNotSignable) {
				t.Fatalf("got %v, want ErrDocumentNotSignable", err)
			}
		})
	}
	if err := checkActiveCeremonyAccess(nil); !errors.Is(err, ErrDocumentNotSignable) {
		t.Fatalf("nil document got %v, want ErrDocumentNotSignable", err)
	}
}

func TestCheckCompletedArtifactAccess(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	completed := &generated.Document{
		Status:      "completed",
		FinalPdfKey: pgtype.Text{String: "org/o/documents/d/final.pdf", Valid: true},
	}

	for _, status := range []string{"signed", "accepted"} {
		t.Run("completed "+status+" recipient may download", func(t *testing.T) {
			row := &generated.GetRecipientByTokenHashRow{
				Status:              status,
				MagicTokenExpiresAt: ts(now.Add(time.Hour)),
			}
			if err := checkCompletedArtifactAccess(row, completed, now); err != nil {
				t.Fatalf("completed artifact access rejected: %v", err)
			}
		})
	}

	cases := []struct {
		name string
		row  *generated.GetRecipientByTokenHashRow
		doc  *generated.Document
	}{
		{"pending recipient", &generated.GetRecipientByTokenHashRow{Status: "pending"}, completed},
		{"viewed recipient", &generated.GetRecipientByTokenHashRow{Status: "viewed"}, completed},
		{"active document", &generated.GetRecipientByTokenHashRow{Status: "signed"}, &generated.Document{Status: "in_progress", FinalPdfKey: completed.FinalPdfKey}},
		{"revised draft", &generated.GetRecipientByTokenHashRow{Status: "signed", MagicTokenExpiresAt: ts(now.Add(time.Hour))}, &generated.Document{Status: "draft", FinalPdfKey: completed.FinalPdfKey}},
		{"voided document", &generated.GetRecipientByTokenHashRow{Status: "signed", MagicTokenExpiresAt: ts(now.Add(time.Hour))}, &generated.Document{Status: "voided", FinalPdfKey: completed.FinalPdfKey}},
		{"missing artifact", &generated.GetRecipientByTokenHashRow{Status: "signed"}, &generated.Document{Status: "completed"}},
		{"blank artifact key", &generated.GetRecipientByTokenHashRow{Status: "signed"}, &generated.Document{Status: "completed", FinalPdfKey: pgtype.Text{Valid: true}}},
		{"missing token expiry", &generated.GetRecipientByTokenHashRow{Status: "signed"}, completed},
		{"expired token", &generated.GetRecipientByTokenHashRow{Status: "signed", MagicTokenExpiresAt: ts(now.Add(-time.Second))}, completed},
		{"token expiring now", &generated.GetRecipientByTokenHashRow{Status: "signed", MagicTokenExpiresAt: ts(now)}, completed},
		{"nil recipient", nil, completed},
		{"nil document", &generated.GetRecipientByTokenHashRow{Status: "signed"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name+" is rejected", func(t *testing.T) {
			if err := checkCompletedArtifactAccess(tc.row, tc.doc, now); !errors.Is(err, ErrCompletedArtifactUnavailable) {
				t.Fatalf("got %v, want ErrCompletedArtifactUnavailable", err)
			}
		})
	}
}

func TestCompletedRecipientTokenStillRejectsMutationAccess(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	row := &generated.GetRecipientByTokenHashRow{
		Status:              "signed",
		MagicTokenExpiresAt: ts(now.Add(time.Hour)),
	}
	doc := &generated.Document{
		Status:      "completed",
		FinalPdfKey: pgtype.Text{String: "org/o/documents/d/final.pdf", Valid: true},
	}
	if err := checkActiveCeremonyAccess(doc); !errors.Is(err, ErrDocumentNotSignable) {
		t.Fatalf("terminal document must fail the ordinary route state gate, got %v", err)
	}
	if err := checkCompletedArtifactAccess(row, doc, now); err != nil {
		t.Fatalf("the read-only completed artifact route should remain available: %v", err)
	}
	if err := checkCompletedArtifactAccess(row, doc, now.Add(2*time.Hour)); !errors.Is(err, ErrCompletedArtifactUnavailable) {
		t.Fatalf("expired completed artifact credential should be rejected, got %v", err)
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
