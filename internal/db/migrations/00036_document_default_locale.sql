-- +goose Up
-- Document-level default signing language. The sender dictates the language a
-- document is sent in; every new recipient inherits this unless the sender
-- overrides it per recipient. Drives the invite/reminder emails, the signer
-- ceremony, and the rendered document together so nothing mixes languages.
-- Same locale codes as the frontend i18n layer; defaults to English.
ALTER TABLE documents ADD COLUMN default_locale TEXT NOT NULL DEFAULT 'en';

-- +goose Down
ALTER TABLE documents DROP COLUMN default_locale;
