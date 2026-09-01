-- +goose Up
-- Additive schema phase for application-layer encryption of outbound webhook
-- signing keys. This migration intentionally does not copy `secret`: SQL never
-- receives the encryption key. Server/worker startup performs the authenticated
-- application backfill, atomically writing ciphertext and blanking plaintext.
--
-- NULL means a legacy row still needs conversion. A non-NULL value, including
-- an invalid/empty BYTEA, is treated as ciphertext and must authenticate; runtime
-- code never falls back to plaintext once this column is present for a row.
ALTER TABLE webhook_endpoints
    ADD COLUMN secret_ciphertext BYTEA;

COMMENT ON COLUMN webhook_endpoints.secret_ciphertext IS
    'Versioned AES-256-GCM envelope; AAD binds org_id and endpoint id. NULL only during legacy backfill.';

-- +goose Down
-- Dropping the ciphertext column after application backfill would destroy the
-- only durable copy of every endpoint secret. Permit rollback only if no row
-- has crossed that boundary; otherwise require forward remediation.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM webhook_endpoints WHERE secret_ciphertext IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'cannot roll back encrypted webhook secrets: ciphertext rows exist';
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE webhook_endpoints DROP COLUMN secret_ciphertext;
