-- +goose Up
-- A PDF source cannot be put under seven-year COMPLIANCE retention inside the
-- same atomic transaction as document/send state. Introduce a durable sealing
-- state and intent so retention happens only after the draft has stopped being
-- editable/deletable, and any crash after retention is resumed to `sent`
-- instead of exposing the retained object as an ordinary draft.

ALTER TABLE documents DROP CONSTRAINT documents_status_check;
ALTER TABLE documents ADD CONSTRAINT documents_status_check
    CHECK (status IN (
        'draft','sealing','sent','in_progress','completed','declined',
        'voided','expired','changes_requested'
    ));

CREATE TABLE send_sealing_intents (
    document_id              UUID PRIMARY KEY REFERENCES documents(id) ON DELETE RESTRICT,
    org_id                   UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    actor_user_id            UUID,
    actor_email              TEXT NOT NULL DEFAULT '',
    actor_ip                 TEXT NOT NULL DEFAULT '',
    via                      TEXT NOT NULL DEFAULT 'worker',
    tool                     TEXT NOT NULL DEFAULT '',
    retention_started_at     TIMESTAMPTZ,
    retention_completed_at   TIMESTAMPTZ,
    attempts                 INTEGER NOT NULL DEFAULT 0,
    last_error               TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX send_sealing_intents_pending_idx
    ON send_sealing_intents (updated_at, document_id);

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM documents WHERE status = 'sealing') THEN
        RAISE EXCEPTION 'cannot roll back durable send sealing while sealing documents exist';
    END IF;
END $$;
-- +goose StatementEnd

DROP TABLE IF EXISTS send_sealing_intents;
ALTER TABLE documents DROP CONSTRAINT documents_status_check;
ALTER TABLE documents ADD CONSTRAINT documents_status_check
    CHECK (status IN (
        'draft','sent','in_progress','completed','declined',
        'voided','expired','changes_requested'
    ));
