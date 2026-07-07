-- +goose Up

-- v1.1 Yjs collaborative editing. The Hash collab server is a thin
-- relay: clients hold the CRDT state, the server broadcasts updates +
-- persists a snapshot so a fresh client gets the current document
-- state at connect time. We don't decode the CRDT server-side; the
-- blob is opaque bytes that Yjs's Y.applyUpdate stitches together on
-- the client.
--
-- Schema choices:
--
--   * One row per document, keyed by document_id (PK). The CRDT is
--     monotonic so we only ever overwrite with newer state.
--   * state_vector + update_log split lets the server hand a fresh
--     client just the deltas they're missing if we want to optimize
--     later; today we always send the full state blob.
--   * collab_presence_token is a per-document HMAC seed so a doc-scope
--     agent token can also connect without flashing the org session
--     cookie (matches the v1.1 scoped-agent-token primitive).

CREATE TABLE collab_doc_states (
    document_id     UUID PRIMARY KEY REFERENCES documents(id) ON DELETE CASCADE,
    ydoc_state      BYTEA NOT NULL DEFAULT ''::bytea,
    state_size      INT NOT NULL DEFAULT 0,
    update_count    INT NOT NULL DEFAULT 0,
    last_user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_collab_doc_states_updated ON collab_doc_states(updated_at DESC);

-- +goose Down

DROP INDEX IF EXISTS idx_collab_doc_states_updated;
DROP TABLE IF EXISTS collab_doc_states;
