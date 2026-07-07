-- +goose Up
CREATE TABLE recipients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id         UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    role                TEXT NOT NULL DEFAULT 'signer'
                        CHECK (role IN ('signer','approver','cc','viewer')),
    email               TEXT NOT NULL,
    name                TEXT NOT NULL,
    order_index         INTEGER NOT NULL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','sent','viewed','signed','declined','bounced')),
    magic_token_hash    BYTEA NOT NULL,
    sent_at             TIMESTAMPTZ,
    first_viewed_at     TIMESTAMPTZ,
    signed_at           TIMESTAMPTZ,
    declined_reason     TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_recipients_document ON recipients(document_id);
CREATE INDEX idx_recipients_token ON recipients(magic_token_hash);
CREATE INDEX idx_recipients_email ON recipients(email);

-- +goose Down
DROP TABLE recipients;
