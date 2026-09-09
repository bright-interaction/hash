// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e || demo

package e2e

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const completeFrozenBrandingFixtureSQL = `INSERT INTO document_branding_override (
	document_id, primary_hex, accent_hex, surface_hex, text_hex, muted_hex,
	logo_url, logo_alt, font_heading, font_body, signature_color
) VALUES ($1, '#0F172A', '#3B82F6', '#FFFFFF', '#0F172A', '#64748B',
	      '', '', 'Inter', 'Inter', '#0F172A')
ON CONFLICT (document_id) DO UPDATE SET
	primary_hex=EXCLUDED.primary_hex, accent_hex=EXCLUDED.accent_hex,
	surface_hex=EXCLUDED.surface_hex, text_hex=EXCLUDED.text_hex,
	muted_hex=EXCLUDED.muted_hex, logo_url=EXCLUDED.logo_url,
	logo_alt=EXCLUDED.logo_alt, font_heading=EXCLUDED.font_heading,
	font_body=EXCLUDED.font_body, signature_color=EXCLUDED.signature_color`

func seedCompleteFrozenBrandingFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, documentID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(ctx, completeFrozenBrandingFixtureSQL, documentID); err != nil {
		t.Fatalf("seed complete canonical frozen branding: %v", err)
	}
}
