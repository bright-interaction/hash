-- +goose Up
-- Templates and documents. Both can be either block-authored (primary)
-- or PDF-uploaded (legacy).

CREATE TABLE templates (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    source_kind       TEXT NOT NULL CHECK (source_kind IN ('blocks','pdf')),
    blocks_json       JSONB,
    variables_json    JSONB NOT NULL DEFAULT '[]'::jsonb,
    pdf_storage_key   TEXT,
    pdf_sha256        BYTEA,
    page_count        INTEGER,
    fields_json       JSONB NOT NULL DEFAULT '[]'::jsonb,
    version           INTEGER NOT NULL DEFAULT 1,
    created_by        UUID NOT NULL REFERENCES users(id),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived_at       TIMESTAMPTZ,
    CONSTRAINT templates_source_consistent CHECK (
        (source_kind = 'blocks' AND blocks_json IS NOT NULL)
        OR
        (source_kind = 'pdf' AND pdf_storage_key IS NOT NULL)
    )
);

CREATE INDEX idx_templates_org_active ON templates(org_id) WHERE archived_at IS NULL;

CREATE TABLE documents (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    template_id       UUID REFERENCES templates(id) ON DELETE SET NULL,
    name              TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'draft'
                      CHECK (status IN ('draft','sent','in_progress','completed','declined','voided','expired')),
    routing_mode      TEXT NOT NULL DEFAULT 'parallel'
                      CHECK (routing_mode IN ('parallel','sequential')),
    source_kind       TEXT NOT NULL CHECK (source_kind IN ('blocks','pdf')),
    blocks_json       JSONB,
    variables_json    JSONB NOT NULL DEFAULT '{}'::jsonb,
    rendered_pdf_key  TEXT,
    rendered_pdf_sha  BYTEA,
    pdf_storage_key   TEXT,
    pdf_sha256        BYTEA,
    final_pdf_key     TEXT,
    final_pdf_sha     BYTEA,
    audit_cert_key    TEXT,
    expires_at        TIMESTAMPTZ,
    sent_at           TIMESTAMPTZ,
    completed_at      TIMESTAMPTZ,
    sender_id         UUID NOT NULL REFERENCES users(id),
    metadata          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_documents_org_status ON documents(org_id, status);
CREATE INDEX idx_documents_expires ON documents(expires_at)
    WHERE status IN ('sent','in_progress');

-- +goose Down
DROP TABLE documents;
DROP TABLE templates;
