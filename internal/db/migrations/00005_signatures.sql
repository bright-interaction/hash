-- +goose Up
CREATE TABLE signatures (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id         UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    recipient_id        UUID NOT NULL REFERENCES recipients(id) ON DELETE CASCADE,
    field_id            UUID NOT NULL REFERENCES document_fields(id) ON DELETE CASCADE,
    font                TEXT NOT NULL,
    typed_name          TEXT NOT NULL,
    image_storage_key   TEXT NOT NULL,
    image_sha256        BYTEA NOT NULL,
    signer_ip           INET,
    signer_ua           TEXT,
    signed_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_signatures_document ON signatures(document_id);
CREATE INDEX idx_signatures_recipient ON signatures(recipient_id);

-- +goose Down
DROP TABLE signatures;
