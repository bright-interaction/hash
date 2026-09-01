-- +goose Up
-- A machine caller must be able to retry an ambiguous e-signature request
-- without creating or sending a second document. Keep only domain-separated
-- SHA-256 correlations for the caller's idempotency key and canonical request;
-- the raw provider delivery id and customer payload do not belong in this
-- long-lived control table.
CREATE TABLE automation_signature_requests (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id               UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    idempotency_key_hash BYTEA NOT NULL
        CHECK (octet_length(idempotency_key_hash) = 32),
    request_hash         BYTEA NOT NULL
        CHECK (octet_length(request_hash) = 32),
    -- SET NULL deliberately preserves the replay tombstone after the existing
    -- 90-day hard purge of a soft-deleted draft. A late retry receives 410 and
    -- can never recreate the same logical request.
    document_id          UUID REFERENCES documents(id) ON DELETE SET NULL,
    state                TEXT NOT NULL DEFAULT 'claimed'
        CHECK (state IN ('claimed', 'ready', 'sent')),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, idempotency_key_hash)
);

CREATE INDEX idx_automation_signature_requests_document
    ON automation_signature_requests (document_id)
    WHERE document_id IS NOT NULL;

-- The composite endpoint is neither a browser REST mutation nor JSON-RPC MCP.
-- Preserve that provenance in the frozen lawful-basis confirmation and send
-- intent instead of mislabelling an automation as a human action.
ALTER TABLE document_lawful_basis_confirmations
    DROP CONSTRAINT document_lawful_basis_confirmations_via_check;
ALTER TABLE document_lawful_basis_confirmations
    ADD CONSTRAINT document_lawful_basis_confirmations_via_check
    CHECK (via IN ('rest','mcp','worker','test','demo','automation'));

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    LOCK TABLE automation_signature_requests IN ACCESS EXCLUSIVE MODE;
    LOCK TABLE document_lawful_basis_confirmations IN ACCESS EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM automation_signature_requests LIMIT 1)
       OR EXISTS (
           SELECT 1 FROM document_lawful_basis_confirmations
           WHERE via = 'automation'
           LIMIT 1
       ) THEN
        RAISE EXCEPTION
            'cannot roll back migration 00063 after durable automation signature requests exist; preserve replay protection';
    END IF;
END
$$;
-- +goose StatementEnd

ALTER TABLE document_lawful_basis_confirmations
    DROP CONSTRAINT document_lawful_basis_confirmations_via_check;
ALTER TABLE document_lawful_basis_confirmations
    ADD CONSTRAINT document_lawful_basis_confirmations_via_check
    CHECK (via IN ('rest','mcp','worker','test','demo'));

DROP TABLE automation_signature_requests;
