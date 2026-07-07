-- name: GetOrgBranding :one
SELECT * FROM org_branding WHERE org_id = $1;

-- name: UpsertOrgBranding :one
INSERT INTO org_branding (
    org_id, primary_hex, accent_hex, surface_hex, text_hex, muted_hex,
    logo_url, logo_alt, font_heading, font_body, signature_color
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
)
ON CONFLICT (org_id) DO UPDATE SET
    primary_hex     = EXCLUDED.primary_hex,
    accent_hex      = EXCLUDED.accent_hex,
    surface_hex     = EXCLUDED.surface_hex,
    text_hex        = EXCLUDED.text_hex,
    muted_hex       = EXCLUDED.muted_hex,
    logo_url        = EXCLUDED.logo_url,
    logo_alt        = EXCLUDED.logo_alt,
    font_heading    = EXCLUDED.font_heading,
    font_body       = EXCLUDED.font_body,
    signature_color = EXCLUDED.signature_color,
    updated_at      = now()
RETURNING *;

-- name: GetDocumentBrandingOverride :one
SELECT * FROM document_branding_override WHERE document_id = $1;

