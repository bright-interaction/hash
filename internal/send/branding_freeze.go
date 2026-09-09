// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/db/generated"
)

const freezeDocumentBrandingSQL = `
INSERT INTO document_branding_override (
    document_id, primary_hex, accent_hex, surface_hex, text_hex, muted_hex,
    logo_url, logo_alt, font_heading, font_body, signature_color
)
SELECT d.id,
       COALESCE(NULLIF(existing.primary_hex, ''), NULLIF(org.primary_hex, ''), $3),
       COALESCE(NULLIF(existing.accent_hex, ''), NULLIF(org.accent_hex, ''), $4),
       COALESCE(NULLIF(existing.surface_hex, ''), NULLIF(org.surface_hex, ''), $5),
       COALESCE(NULLIF(existing.text_hex, ''), NULLIF(org.text_hex, ''), $6),
       COALESCE(NULLIF(existing.muted_hex, ''), NULLIF(org.muted_hex, ''), $7),
       COALESCE(NULLIF(existing.logo_url, ''), NULLIF(org.logo_url, ''), $8),
       COALESCE(NULLIF(existing.logo_alt, ''), NULLIF(org.logo_alt, ''), $9),
       COALESCE(NULLIF(existing.font_heading, ''), NULLIF(org.font_heading, ''), $10),
       COALESCE(NULLIF(existing.font_body, ''), NULLIF(org.font_body, ''), $11),
       COALESCE(NULLIF(existing.signature_color, ''), NULLIF(org.signature_color, ''), $12)
  FROM documents d
  LEFT JOIN org_branding org ON org.org_id = d.org_id
  LEFT JOIN document_branding_override existing ON existing.document_id = d.id
 WHERE d.id = $1 AND d.org_id = $2
ON CONFLICT (document_id) DO UPDATE SET
    primary_hex = EXCLUDED.primary_hex,
    accent_hex = EXCLUDED.accent_hex,
    surface_hex = EXCLUDED.surface_hex,
    text_hex = EXCLUDED.text_hex,
    muted_hex = EXCLUDED.muted_hex,
    logo_url = EXCLUDED.logo_url,
    logo_alt = EXCLUDED.logo_alt,
    font_heading = EXCLUDED.font_heading,
    font_body = EXCLUDED.font_body,
    signature_color = EXCLUDED.signature_color,
    updated_at = now()
RETURNING document_id, primary_hex, accent_hex, surface_hex, text_hex,
          muted_hex, logo_url, logo_alt, font_heading, font_body,
          signature_color`

// freezeDocumentBranding materializes every effective field into the document
// override in the caller's existing send transaction. The document has already
// been selected FOR UPDATE, so a successful return is tied atomically to the
// later sealing transition. The returned logo URL lets Send reject the
// unsupported asset in every environment before that transaction commits.
type brandingSnapshotQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func freezeDocumentBranding(ctx context.Context, tx brandingSnapshotQuerier, doc *generated.Document) (string, error) {
	if tx == nil || doc == nil {
		return "", errors.New("freeze document branding: lifecycle snapshot unavailable")
	}
	defaults := branding.DefaultBranding()
	var snapshot generated.DocumentBrandingOverride
	err := tx.QueryRow(ctx, freezeDocumentBrandingSQL,
		doc.ID, doc.OrgID,
		defaults.PrimaryHex, defaults.AccentHex, defaults.SurfaceHex,
		defaults.TextHex, defaults.MutedHex, defaults.LogoURL, defaults.LogoAlt,
		defaults.FontHeading, defaults.FontBody, defaults.SignatureColor,
	).Scan(
		&snapshot.DocumentID, &snapshot.PrimaryHex, &snapshot.AccentHex,
		&snapshot.SurfaceHex, &snapshot.TextHex, &snapshot.MutedHex,
		&snapshot.LogoUrl, &snapshot.LogoAlt, &snapshot.FontHeading,
		&snapshot.FontBody, &snapshot.SignatureColor,
	)
	if err != nil {
		return "", errors.New("freeze document branding: persist complete snapshot")
	}
	if err := branding.ValidateFrozenSnapshot(doc.ID, &snapshot); err != nil {
		return "", fmt.Errorf("freeze document branding: validate complete snapshot: %w", err)
	}
	return snapshot.LogoUrl.String, nil
}
