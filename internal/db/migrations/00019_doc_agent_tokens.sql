-- +goose Up

-- v1.1: per-document scoped agent tokens. Lets a sender hand a specific
-- agent (or a specific MCP-attached workflow) a time-bounded token that
-- can ONLY operate on one document, without minting a full org-wide API
-- key. Tokens live in their own table so the api_keys table stays a
-- clean "production credentials" surface.
--
-- Key format: same `mth_<prefix>_<secret>` as api_keys so the existing
-- bearer-token middleware doesn't need a parser rewrite; the verifier
-- looks up api_keys first, then falls back to document_agent_tokens.
-- Hashing is sha256 of the full plaintext, just like api_keys.

CREATE TABLE document_agent_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id  UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name         TEXT NOT NULL DEFAULT '',
    prefix       TEXT NOT NULL UNIQUE,            -- 8 hex chars; the api_key parser routes on this
    key_hash     BYTEA NOT NULL,
    scopes       TEXT[] NOT NULL DEFAULT ARRAY['read']::text[],
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    max_uses     INT NOT NULL DEFAULT 0,          -- 0 = unlimited until expiry
    used_count   INT NOT NULL DEFAULT 0,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_doc_agent_tokens_doc ON document_agent_tokens(document_id);
CREATE INDEX idx_doc_agent_tokens_org_active
    ON document_agent_tokens(org_id, revoked_at, expires_at)
    WHERE revoked_at IS NULL;

-- +goose Down

DROP INDEX idx_doc_agent_tokens_org_active;
DROP INDEX idx_doc_agent_tokens_doc;
DROP TABLE document_agent_tokens;
