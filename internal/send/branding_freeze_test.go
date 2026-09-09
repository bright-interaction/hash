// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/db/generated"
)

type brandingSnapshotRow struct {
	snapshot generated.DocumentBrandingOverride
	err      error
}

func (r brandingSnapshotRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 11 {
		return errors.New("unexpected branding snapshot destination")
	}
	values := []any{
		r.snapshot.DocumentID, r.snapshot.PrimaryHex, r.snapshot.AccentHex,
		r.snapshot.SurfaceHex, r.snapshot.TextHex, r.snapshot.MutedHex,
		r.snapshot.LogoUrl, r.snapshot.LogoAlt, r.snapshot.FontHeading,
		r.snapshot.FontBody, r.snapshot.SignatureColor,
	}
	for i, target := range dest {
		switch typed := target.(type) {
		case *uuid.UUID:
			value, ok := values[i].(uuid.UUID)
			if !ok {
				return errors.New("unexpected UUID snapshot value")
			}
			*typed = value
		case *pgtype.Text:
			value, ok := values[i].(pgtype.Text)
			if !ok {
				return errors.New("unexpected text snapshot value")
			}
			*typed = value
		default:
			return errors.New("unexpected branding snapshot destination type")
		}
	}
	return nil
}

func completeBrandingSnapshot(documentID uuid.UUID) generated.DocumentBrandingOverride {
	text := func(value string) pgtype.Text { return pgtype.Text{String: value, Valid: true} }
	return generated.DocumentBrandingOverride{
		DocumentID: documentID, PrimaryHex: text("#0F172A"), AccentHex: text("#3B82F6"),
		SurfaceHex: text("#FFFFFF"), TextHex: text("#0F172A"), MutedHex: text("#64748B"),
		LogoUrl: text(""), LogoAlt: text(""), FontHeading: text("Inter"),
		FontBody: text("Inter"), SignatureColor: text("#0F172A"),
	}
}

type brandingSnapshotDB struct {
	query string
	args  []any
	row   pgx.Row
}

func (db *brandingSnapshotDB) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	db.query = query
	db.args = args
	return db.row
}

func TestFreezeDocumentBrandingPersistsCompleteEffectiveSnapshot(t *testing.T) {
	t.Parallel()
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New()}
	db := &brandingSnapshotDB{row: brandingSnapshotRow{snapshot: completeBrandingSnapshot(doc.ID)}}
	logo, err := freezeDocumentBranding(context.Background(), db, doc)
	if err != nil || logo != "" {
		t.Fatalf("freeze result = %q, %v", logo, err)
	}
	if len(db.args) != 12 || db.args[0] != doc.ID || db.args[1] != doc.OrgID {
		t.Fatalf("snapshot args = %#v", db.args)
	}
	for _, required := range []string{
		"LEFT JOIN org_branding",
		"LEFT JOIN document_branding_override existing",
		"COALESCE(NULLIF(existing.primary_hex, ''), NULLIF(org.primary_hex, ''), $3)",
		"ON CONFLICT (document_id) DO UPDATE",
		"RETURNING document_id, primary_hex, accent_hex, surface_hex, text_hex",
		"muted_hex, logo_url, logo_alt, font_heading, font_body",
	} {
		if !strings.Contains(db.query, required) {
			t.Fatalf("branding snapshot query lost clause %q", required)
		}
	}
}

func TestFreezeDocumentBrandingValidatesEveryReturnedFieldBeforeSealing(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mutate func(*generated.DocumentBrandingOverride)
	}{
		{name: "missing field", mutate: func(row *generated.DocumentBrandingOverride) { row.SurfaceHex.Valid = false }},
		{name: "invalid color", mutate: func(row *generated.DocumentBrandingOverride) { row.PrimaryHex.String = "not-a-color" }},
		{name: "whitespace font", mutate: func(row *generated.DocumentBrandingOverride) { row.FontBody.String = "\t\n" }},
		{name: "noncanonical font", mutate: func(row *generated.DocumentBrandingOverride) { row.FontHeading.String = " Inter" }},
		{name: "invalid logo", mutate: func(row *generated.DocumentBrandingOverride) { row.LogoUrl.String = "javascript:alert(1)" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New()}
			snapshot := completeBrandingSnapshot(doc.ID)
			tc.mutate(&snapshot)
			db := &brandingSnapshotDB{row: brandingSnapshotRow{snapshot: snapshot}}
			if _, err := freezeDocumentBranding(context.Background(), db, doc); !errors.Is(err, branding.ErrFrozenBrandingUnavailable) {
				t.Fatalf("freeze invalid snapshot error = %v, want frozen-branding refusal", err)
			}
		})
	}
}

func TestFreezeDocumentBrandingFailsClosedWithoutSnapshot(t *testing.T) {
	t.Parallel()
	if _, err := freezeDocumentBranding(context.Background(), nil, &generated.Document{}); err == nil {
		t.Fatal("nil snapshot store was accepted")
	}
	db := &brandingSnapshotDB{row: brandingSnapshotRow{err: errors.New("database detail")}}
	if _, err := freezeDocumentBranding(context.Background(), db, &generated.Document{ID: uuid.New(), OrgID: uuid.New()}); err == nil || strings.Contains(err.Error(), "database detail") {
		t.Fatalf("snapshot failure was accepted or leaked details: %v", err)
	}
}

func TestSendFreezesRootAndEnvelopeChildrenBeforeSealingIntent(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("engine.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	freeze := strings.Index(source, "brandingDocs := append([]*generated.Document{doc}, envelopeChildren...)")
	seal := strings.Index(source, "q.CreateSendSealingIntent")
	if freeze < 0 || seal < 0 || freeze >= seal {
		t.Fatalf("branding freeze must cover the root and envelope children before sealing: freeze=%d seal=%d", freeze, seal)
	}
}
