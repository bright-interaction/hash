-- +goose Up
-- Event subject/actor UUIDs are part of row_hash. A foreign key with
-- ON DELETE SET NULL silently mutates that hashed input when a draft recipient,
-- draft document, or user is removed and therefore makes the org chain fail
-- verification. Audit-ledger identifiers intentionally outlive their live
-- application rows, so keep the indexed UUID values but remove mutating FKs.
ALTER TABLE events DROP CONSTRAINT IF EXISTS events_document_id_fkey;
ALTER TABLE events DROP CONSTRAINT IF EXISTS events_recipient_id_fkey;
ALTER TABLE events DROP CONSTRAINT IF EXISTS events_actor_user_id_fkey;

-- +goose Down
-- A rollback may encounter identifiers whose live rows were deleted while the
-- immutable-reference migration was active. Null them before restoring the
-- legacy constraints; rolling this migration back knowingly gives up the
-- chain-preservation guarantee documented above.
UPDATE events e
SET document_id = NULL
WHERE document_id IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM documents d WHERE d.id = e.document_id);

UPDATE events e
SET recipient_id = NULL
WHERE recipient_id IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM recipients r WHERE r.id = e.recipient_id);

UPDATE events e
SET actor_user_id = NULL
WHERE actor_user_id IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = e.actor_user_id);

ALTER TABLE events
    ADD CONSTRAINT events_document_id_fkey
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE SET NULL;
ALTER TABLE events
    ADD CONSTRAINT events_recipient_id_fkey
    FOREIGN KEY (recipient_id) REFERENCES recipients(id) ON DELETE SET NULL;
ALTER TABLE events
    ADD CONSTRAINT events_actor_user_id_fkey
    FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL;
