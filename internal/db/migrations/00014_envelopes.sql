-- +goose Up

-- Phase 8.6: PandaDoc-style multi-document envelopes. One signature
-- ceremony covers N documents that are legally bound as a single
-- instrument. The chosen architecture extends the documents table
-- rather than introducing a new envelope table, so:
--
--   * Every helper (queries, audit log, magic links) already knows
--     how to work with documents.
--   * An envelope is just a document where is_envelope=true.
--   * Child documents carry parent_envelope_id back to the envelope.
--
-- Envelope semantics enforced at the application layer (handler/MCP):
--   * Envelopes (is_envelope=true) have no block tree of their own;
--     content is the ordered concatenation of children's content.
--   * Recipients + signature fields attach to the envelope.
--   * State machine runs at envelope level; child state mirrors parent
--     via the standard set_status helpers, with the parent's transition
--     fanning out to children.
--
-- Constraints:
--   * envelope_not_nested: an envelope cannot itself be a child.
--   * envelope_child_no_envelope: a doc cannot be both a child and an
--     envelope.

ALTER TABLE documents
    ADD COLUMN parent_envelope_id UUID REFERENCES documents(id) ON DELETE CASCADE,
    ADD COLUMN envelope_position  INT,
    ADD COLUMN is_envelope        BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX idx_docs_envelope
    ON documents(parent_envelope_id, envelope_position)
    WHERE parent_envelope_id IS NOT NULL;

CREATE INDEX idx_docs_is_envelope
    ON documents(org_id)
    WHERE is_envelope = TRUE;

ALTER TABLE documents
    ADD CONSTRAINT envelope_not_nested
    CHECK (NOT (is_envelope AND parent_envelope_id IS NOT NULL));

-- +goose Down

ALTER TABLE documents DROP CONSTRAINT envelope_not_nested;
DROP INDEX idx_docs_is_envelope;
DROP INDEX idx_docs_envelope;
ALTER TABLE documents
    DROP COLUMN is_envelope,
    DROP COLUMN envelope_position,
    DROP COLUMN parent_envelope_id;
