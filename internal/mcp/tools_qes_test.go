// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestQESToolsExposeOnlyExplicitHistoricalRead(t *testing.T) {
	s := NewServer()
	registerQESTools(s, Deps{})
	if _, ok := s.tools["start_qes_session"]; ok {
		t.Fatal("start_qes_session must not be registered in the SES-only release")
	}
	tool, ok := s.tools["get_qes_session"]
	if !ok {
		t.Fatal("historical QES archive reader is not registered")
	}
	if tool.Write || tool.MinFeature != "" {
		t.Fatalf("historical reader has mutation/plan gate metadata: Write=%v MinFeature=%q", tool.Write, tool.MinFeature)
	}
	description := strings.ToLower(tool.Description)
	for _, phrase := range []string{"historical", "cannot start", "unverified", "must not be treated"} {
		if !strings.Contains(description, phrase) {
			t.Errorf("description does not disclose %q: %s", phrase, tool.Description)
		}
	}
}

func TestHistoricalQESRecordRejectsLifecycleAndIncompleteRows(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name string
		row  *generated.QesSigningSession
		want error
	}{
		{name: "nil", want: errQESRecordNotArchival},
		{
			name: "pending",
			row: &generated.QesSigningSession{
				Status: "pending",
			},
			want: errQESRecordNotArchival,
		},
		{
			name: "completed without provider proof material",
			row: &generated.QesSigningSession{
				Status:      "completed",
				CompletedAt: pgtype.Timestamptz{Time: now, Valid: true},
			},
			want: errQESRecordIncomplete,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := historicalQESRecord(tc.row); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestHistoricalQESRecordIsClearlyUnverifiedAndOmitsLifecycleSecrets(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	row := &generated.QesSigningSession{
		ID:                    uuid.New(),
		DocumentID:            uuid.New(),
		RecipientID:           uuid.New(),
		Provider:              "legacy-provider",
		ProviderSessionID:     "provider-callback-handle",
		Status:                "completed",
		RedirectUrl:           pgtype.Text{String: "https://provider.example/resume", Valid: true},
		CallbackSecret:        "must-never-leave-the-server",
		IdentityAssertionJson: []byte(`{"legacy":true}`),
		SignatureB64:          pgtype.Text{String: "bGVnYWN5", Valid: true},
		CertChainPem:          pgtype.Text{String: "legacy chain bytes", Valid: true},
		CreatedAt:             pgtype.Timestamptz{Time: now.Add(-time.Hour), Valid: true},
		CompletedAt:           pgtype.Timestamptz{Time: now, Valid: true},
		ExpiresAt:             pgtype.Timestamptz{Time: now.Add(time.Hour), Valid: true},
	}
	out, err := historicalQESRecord(row)
	if err != nil {
		t.Fatal(err)
	}
	if got := out["record_classification"]; got != "unverified_legacy_qes_material" {
		t.Fatalf("record_classification = %v", got)
	}
	if warning, _ := out["warning"].(string); !strings.Contains(warning, "does not validate") || !strings.Contains(warning, "legal effect") {
		t.Fatalf("warning is not explicit enough: %q", warning)
	}
	for _, forbidden := range []string{"provider_session_id", "redirect_url", "callback_secret"} {
		if _, present := out[forbidden]; present {
			t.Errorf("archival response leaked lifecycle field %q", forbidden)
		}
	}
}
