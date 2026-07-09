-- +goose Up
-- Acknowledgement mode: a document can be sent WITHOUT requiring a signature
-- (send it to be read + optionally accepted). requires_signature defaults true
-- so every existing + future document keeps the signature-required behaviour
-- unless a sender explicitly opts a draft into acknowledgement mode.
ALTER TABLE documents ADD COLUMN requires_signature BOOLEAN NOT NULL DEFAULT true;

-- 'accepted' is the acknowledgement-mode counterpart of 'signed': the recipient
-- opened the document and clicked Accept (recorded in the event hash chain), no
-- cryptographic signature.
ALTER TABLE recipients DROP CONSTRAINT recipients_status_check;
ALTER TABLE recipients ADD CONSTRAINT recipients_status_check
    CHECK (status IN ('pending','sent','viewed','signed','declined','bounced','accepted'));

-- +goose Down
ALTER TABLE recipients DROP CONSTRAINT recipients_status_check;
ALTER TABLE recipients ADD CONSTRAINT recipients_status_check
    CHECK (status IN ('pending','sent','viewed','signed','declined','bounced'));
ALTER TABLE documents DROP COLUMN requires_signature;
