-- +goose Up
-- Final PDFs and certificates cross PostgreSQL and S3 Object Lock. Each
-- content-addressed version is written with COMPLIANCE retention atomically,
-- then its exact key/digest is durably checkpointed in `finalizing` before the
-- terminal row is published. Deterministic retries can reuse a locked orphan
-- left by a crash, and the intent records retention read-back completion.

ALTER TABLE documents DROP CONSTRAINT documents_status_check;
ALTER TABLE documents ADD CONSTRAINT documents_status_check
    CHECK (status IN (
        'draft','sealing','sent','in_progress','finalizing','completed',
        'declined','voided','expired','changes_requested'
    ));

CREATE TABLE document_finalization_intents (
    document_id               UUID PRIMARY KEY REFERENCES documents(id) ON DELETE RESTRICT,
    org_id                    UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    mode                      TEXT NOT NULL CHECK (mode IN ('signature','acknowledgement')),
    final_pdf_key             TEXT NOT NULL,
    final_pdf_sha256          BYTEA NOT NULL CHECK (octet_length(final_pdf_sha256) = 32),
    audit_cert_key            TEXT NOT NULL,
    audit_cert_sha256         BYTEA NOT NULL CHECK (octet_length(audit_cert_sha256) = 32),
    audit_payload_key         TEXT NOT NULL,
    audit_payload_sha256      BYTEA NOT NULL CHECK (octet_length(audit_payload_sha256) = 32),
    audit_signature_key       TEXT NOT NULL,
    audit_signature_sha256    BYTEA NOT NULL CHECK (octet_length(audit_signature_sha256) = 32),
    retention_started_at      TIMESTAMPTZ,
    retention_completed_at    TIMESTAMPTZ,
    attempts                  INTEGER NOT NULL DEFAULT 0,
    last_error                TEXT,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (final_pdf_key <> '' AND audit_cert_key <> '' AND audit_payload_key <> '' AND audit_signature_key <> ''),
    -- Bind every logical key to both its owning org/document and the digest
    -- recorded in the intent. In particular documents has no separate
    -- audit-cert SHA column after publication, so this DB constraint prevents
    -- a future caller from pairing an arbitrary cert key with a retained
    -- digest and then satisfying only the terminal EXISTS guard.
    CHECK (final_pdf_key = 'org/' || org_id::text || '/documents/' || document_id::text ||
                           '/final-' || encode(final_pdf_sha256, 'hex') || '.pdf'),
    CHECK (audit_cert_key = 'org/' || org_id::text || '/documents/' || document_id::text ||
                           '/audit-' || encode(audit_cert_sha256, 'hex') || '.pdf'),
    CHECK (audit_payload_key = 'org/' || org_id::text || '/documents/' || document_id::text ||
                              '/audit-payload-' || encode(audit_payload_sha256, 'hex') || '.txt'),
    CHECK (audit_signature_key = 'org/' || org_id::text || '/documents/' || document_id::text ||
                                '/audit-signature-' || encode(audit_signature_sha256, 'hex') || '.txt')
);

CREATE INDEX document_finalization_intents_pending_idx
    ON document_finalization_intents (updated_at, document_id);

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM documents WHERE status = 'finalizing') THEN
        RAISE EXCEPTION 'cannot roll back durable finalization while finalizing documents exist';
    END IF;
END $$;
-- +goose StatementEnd

DROP TABLE IF EXISTS document_finalization_intents;
ALTER TABLE documents DROP CONSTRAINT documents_status_check;
ALTER TABLE documents ADD CONSTRAINT documents_status_check
    CHECK (status IN (
        'draft','sealing','sent','in_progress','completed',
        'declined','voided','expired','changes_requested'
    ));
