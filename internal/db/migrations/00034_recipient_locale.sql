-- +goose Up
-- Per-recipient signing language. The sender sets the counterparty's language
-- so the invite/reminder emails and the signer page open in the right language
-- before the signer even picks one. Defaults to English; the signer can still
-- switch on the page. Uses the same locale codes as the frontend i18n layer.
ALTER TABLE recipients ADD COLUMN locale TEXT NOT NULL DEFAULT 'en';

-- +goose Down
ALTER TABLE recipients DROP COLUMN locale;
