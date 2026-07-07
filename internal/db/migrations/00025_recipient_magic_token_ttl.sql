-- +goose Up
-- Per-recipient magic-link TTL. The signer-token has high entropy (32
-- random bytes) so a brute force isn't the threat; the threat is a token
-- that leaks via email forwarding or a screenshot remaining valid for
-- the entire document lifetime. We now bind every token to a hard
-- expiry, default 30 days from issue (matches the existing send +
-- 30-day reminder window).
--
-- Backfill: keep existing tokens alive for 30 days from now so we don't
-- break in-flight signing flows when the migration applies. New mints
-- (handler/send.go, handler/dispatch.go reminders) clamp to the lesser
-- of documents.expires_at and now() + 30 days.
ALTER TABLE recipients
    ADD COLUMN magic_token_expires_at TIMESTAMPTZ;

UPDATE recipients
SET magic_token_expires_at = COALESCE(
        (SELECT d.expires_at FROM documents d WHERE d.id = recipients.document_id),
        now() + INTERVAL '30 days'
    );

CREATE INDEX idx_recipients_token_expiry
    ON recipients(magic_token_expires_at)
    WHERE magic_token_expires_at IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_recipients_token_expiry;
ALTER TABLE recipients DROP COLUMN IF EXISTS magic_token_expires_at;
