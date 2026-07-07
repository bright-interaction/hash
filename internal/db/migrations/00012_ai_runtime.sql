-- +goose Up

-- Phase 8.4: AI runtime foundation. Two tables land now:
--
--   block_embeddings: per-block embedding vectors keyed by
--     (document_id, block_id, model). Stored as JSONB array for v1 so
--     the migration runs against vanilla Postgres without pgvector. A
--     follow-up migration will swap to pgvector + an HNSW index once
--     real similarity search is needed (Phase 11.1 clarifier RAG).
--
--   ai_completion_audit: every Runtime.Complete call logs here so
--     reviewers can confirm Shield-tokenized PII never reached a
--     provider and so usage cost can be attributed back to docs.

CREATE TABLE block_embeddings (
    document_id  UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    block_id     TEXT NOT NULL,
    model        TEXT NOT NULL,
    dimensions   INT  NOT NULL,
    embedding    JSONB NOT NULL,          -- float32[] as JSON; swap to vector(N) when pgvector lands
    text_snippet TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (document_id, block_id, model)
);

CREATE INDEX idx_block_emb_doc ON block_embeddings(document_id);

CREATE TABLE ai_completion_audit (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    document_id     UUID REFERENCES documents(id) ON DELETE SET NULL,
    actor_user_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    provider        TEXT NOT NULL,                       -- 'mistral' | 'anthropic' | 'noop'
    model           TEXT NOT NULL,
    prompt_name     TEXT NOT NULL DEFAULT '',            -- empty for ad-hoc
    prompt_version  INT NOT NULL DEFAULT 0,
    shield_active   BOOLEAN NOT NULL DEFAULT false,
    input_tokens    INT NOT NULL DEFAULT 0,
    output_tokens   INT NOT NULL DEFAULT 0,
    latency_ms      INT NOT NULL DEFAULT 0,
    success         BOOLEAN NOT NULL,
    error           TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_ai_audit_org ON ai_completion_audit(org_id, created_at DESC);
CREATE INDEX idx_ai_audit_doc ON ai_completion_audit(document_id);

-- +goose Down

DROP TABLE ai_completion_audit;
DROP TABLE block_embeddings;
