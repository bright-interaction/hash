-- +goose Up
-- Backstop the application-level idempotency check for same-recipient
-- double-POST: exactly one signature per recipient per document. Without
-- this, a concurrent double-POST that slips past the stale in-memory status
-- check inserts duplicate signature rows. Dedupe any pre-existing violations
-- (keep the earliest by (signed_at, id)) before creating the unique index so
-- the CREATE cannot fail on legacy data.
DELETE FROM signatures s
USING signatures s2
WHERE s.document_id = s2.document_id
  AND s.recipient_id = s2.recipient_id
  AND (s.signed_at, s.id) > (s2.signed_at, s2.id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_signatures_document_recipient
    ON signatures(document_id, recipient_id);

-- +goose Down
DROP INDEX IF EXISTS uq_signatures_document_recipient;
