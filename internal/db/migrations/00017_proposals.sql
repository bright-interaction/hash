-- +goose Up

-- Phase 11.2 (#3): negotiation copilot with redlines. Recipients can
-- propose counter-clauses; senders see a redline diff and accept /
-- reject. Versioning (Phase 8.1) is the substrate: every accepted
-- proposal becomes a new document version.
--
-- proposal_kind:
--   'edit'         the recipient suggests revised text for a clause
--   'reject'       the recipient asks the sender to drop the clause
--   'counter'      the sender's reply to a recipient proposal (chain)
--   'block_lock'   the sender marks a clause non-negotiable
--
-- status:
--   'pending'      submitted, awaiting the other side
--   'accepted'     applied to a new document version
--   'rejected'     dismissed by the other side
--   'superseded'   replaced by a later proposal in the same chain

CREATE TABLE document_proposals (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id   UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    recipient_id  UUID REFERENCES recipients(id) ON DELETE SET NULL,
    proposed_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    block_id      TEXT NOT NULL,
    proposal_kind TEXT NOT NULL CHECK (proposal_kind IN ('edit','reject','counter','block_lock')),
    proposed_text TEXT NOT NULL DEFAULT '',
    rationale     TEXT NOT NULL DEFAULT '',
    diff_json     JSONB NOT NULL DEFAULT '{}'::jsonb,
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','accepted','rejected','superseded')),
    ai_assisted   BOOLEAN NOT NULL DEFAULT FALSE,
    parent_id     UUID REFERENCES document_proposals(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_proposals_doc ON document_proposals(document_id, created_at DESC);
CREATE INDEX idx_proposals_block ON document_proposals(document_id, block_id, status);

-- documents gains a flag controlling whether the signer-side
-- negotiation UI is available. Default off (opt-in per doc).
ALTER TABLE documents
    ADD COLUMN negotiation_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN bilingual_target_lang TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE documents
    DROP COLUMN bilingual_target_lang,
    DROP COLUMN negotiation_enabled;
DROP INDEX idx_proposals_block;
DROP INDEX idx_proposals_doc;
DROP TABLE document_proposals;
