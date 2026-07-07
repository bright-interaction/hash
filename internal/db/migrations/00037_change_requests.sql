-- +goose Up
-- Negotiation loop: a signer can request changes instead of signing. The
-- document pauses in 'changes_requested', the sender revises it (back to draft)
-- and re-sends the new draft for signature. change_requests records the asks.
ALTER TABLE documents DROP CONSTRAINT documents_status_check;
ALTER TABLE documents ADD CONSTRAINT documents_status_check
    CHECK (status IN ('draft','sent','in_progress','completed','declined','voided','expired','changes_requested'));

CREATE TABLE change_requests (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id   UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    recipient_id  UUID REFERENCES recipients(id) ON DELETE SET NULL,
    message       TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open','resolved')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at   TIMESTAMPTZ
);
CREATE INDEX idx_change_requests_document ON change_requests(document_id);

-- +goose Down
DROP TABLE change_requests;
ALTER TABLE documents DROP CONSTRAINT documents_status_check;
ALTER TABLE documents ADD CONSTRAINT documents_status_check
    CHECK (status IN ('draft','sent','in_progress','completed','declined','voided','expired'));
