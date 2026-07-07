-- +goose Up

-- Phase 8.5: org-level brand theming. Every org gets a single row that
-- defines the colour palette, logo URL, and font pair used to render
-- the org's documents in the browser signer AND in the Gotenberg PDF.
-- The block tree itself stays brand-agnostic; themes apply purely at the
-- rendering layer via CSS custom properties.
--
-- Pattern lifted from atomicsite/internal/builder/cookieproof_theme.go:
-- one Branding row -> map of CSS custom property names -> string values
-- -> emitted as <style>:root { --hash-accent: #...; }</style> at the
-- top of every render.

CREATE TABLE org_branding (
    org_id          UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    primary_hex     TEXT NOT NULL DEFAULT '#0F172A',
    accent_hex      TEXT NOT NULL DEFAULT '#3B82F6',
    surface_hex     TEXT NOT NULL DEFAULT '#FFFFFF',
    text_hex        TEXT NOT NULL DEFAULT '#0F172A',
    muted_hex       TEXT NOT NULL DEFAULT '#64748B',
    logo_url        TEXT NOT NULL DEFAULT '',
    logo_alt        TEXT NOT NULL DEFAULT '',
    font_heading    TEXT NOT NULL DEFAULT 'Inter',
    font_body       TEXT NOT NULL DEFAULT 'Inter',
    signature_color TEXT NOT NULL DEFAULT '#0F172A',
    schema_version  INT NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-document branding overrides for the rare case a doc needs to break
-- from the org theme (e.g. a co-branded contract). Same shape as
-- org_branding minus the FK-key composition.
CREATE TABLE document_branding_override (
    document_id     UUID PRIMARY KEY REFERENCES documents(id) ON DELETE CASCADE,
    primary_hex     TEXT,
    accent_hex      TEXT,
    surface_hex     TEXT,
    text_hex        TEXT,
    muted_hex       TEXT,
    logo_url        TEXT,
    logo_alt        TEXT,
    font_heading    TEXT,
    font_body       TEXT,
    signature_color TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down

DROP TABLE document_branding_override;
DROP TABLE org_branding;
