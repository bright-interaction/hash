-- +goose Up

CREATE TABLE document_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id     UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    version_no      INT NOT NULL,
    block_tree_json JSONB,
    variables_json  JSONB NOT NULL DEFAULT '{}'::jsonb,
    name            TEXT NOT NULL,
    source_kind     TEXT NOT NULL CHECK (source_kind IN ('blocks','pdf')),
    summary         TEXT NOT NULL DEFAULT '',
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_via     TEXT NOT NULL DEFAULT 'human'
                    CHECK (created_via IN ('human','mcp','crm-bind','agent','restore','import')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    parent_id       UUID REFERENCES document_versions(id) ON DELETE SET NULL,
    schema_version  INT NOT NULL DEFAULT 1,
    UNIQUE (document_id, version_no)
);

CREATE INDEX idx_versions_doc ON document_versions(document_id, version_no DESC);
CREATE INDEX idx_versions_org ON document_versions(org_id, created_at DESC);

-- +goose Down

DROP TABLE document_versions;
