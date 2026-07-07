-- +goose Up
-- Belt-and-suspenders behind the send-engine extraction: make
-- magic_token_expires_at fail CLOSED at the DB level. The TTL fix had been
-- applied per-surface, so the MCP + worker paths minted tokens with a NULL
-- expiry that LookupByToken treats as "no expiry" (fails open). With every
-- producer now routed through the send engine they always set the expiry,
-- but a NOT NULL column with a 30-day default means any future raw write
-- that forgets the field still gets a bounded value instead of an
-- unbounded link. Backfill any existing NULLs first so the constraint can
-- be added.
ALTER TABLE recipients ALTER COLUMN magic_token_expires_at SET DEFAULT (now() + interval '30 days');
UPDATE recipients SET magic_token_expires_at = now() + interval '30 days' WHERE magic_token_expires_at IS NULL;
ALTER TABLE recipients ALTER COLUMN magic_token_expires_at SET NOT NULL;

-- +goose Down
ALTER TABLE recipients ALTER COLUMN magic_token_expires_at DROP NOT NULL;
ALTER TABLE recipients ALTER COLUMN magic_token_expires_at DROP DEFAULT;
