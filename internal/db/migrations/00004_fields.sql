-- +goose Up
CREATE TABLE document_fields (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id     UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    recipient_id    UUID REFERENCES recipients(id) ON DELETE CASCADE,
    type            TEXT NOT NULL
                    CHECK (type IN ('signature','initial','text','date','checkbox','dropdown','date_signed','name_auto')),
    page            INTEGER NOT NULL,
    x_pct           NUMERIC(7,4) NOT NULL,
    y_pct           NUMERIC(7,4) NOT NULL,
    w_pct           NUMERIC(7,4) NOT NULL,
    h_pct           NUMERIC(7,4) NOT NULL,
    required        BOOLEAN NOT NULL DEFAULT TRUE,
    label           TEXT,
    options_json    JSONB NOT NULL DEFAULT '{}'::jsonb,
    value           TEXT,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_fields_document ON document_fields(document_id);
CREATE INDEX idx_fields_recipient ON document_fields(recipient_id);

-- +goose Down
DROP TABLE document_fields;
