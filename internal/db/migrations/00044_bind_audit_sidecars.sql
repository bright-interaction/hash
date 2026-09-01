-- +goose Up
-- Persist the exact detached certificate payload and signature objects that
-- belong to a terminal document. S3 Object Lock protects existing versions,
-- but a newer version at the same logical key can otherwise shadow them. The
-- digest-addressed key plus the independently stored SHA-256 lets every read
-- select and verify the authentic bytes instead of trusting "latest".

ALTER TABLE documents
    ADD COLUMN audit_payload_key TEXT,
    ADD COLUMN audit_payload_sha256 BYTEA,
    ADD COLUMN audit_signature_key TEXT,
    ADD COLUMN audit_signature_sha256 BYTEA;

ALTER TABLE documents
    ADD CONSTRAINT documents_audit_payload_evidence_pair_chk CHECK (
        -- CHECK accepts SQL UNKNOWN, so a simple `(both NULL) OR (both
        -- present)` expression is not enough: a half-populated pair can make
        -- the second branch UNKNOWN and slip through. Equality of the two
        -- IS-NULL predicates is always boolean and closes that hole.
        (audit_payload_key IS NULL) = (audit_payload_sha256 IS NULL)
        AND (
            audit_payload_key IS NULL
            OR (
                btrim(audit_payload_key) <> ''
                AND octet_length(audit_payload_sha256) = 32
            )
        )
    ),
    ADD CONSTRAINT documents_audit_signature_evidence_pair_chk CHECK (
        (audit_signature_key IS NULL) = (audit_signature_sha256 IS NULL)
        AND (
            audit_signature_key IS NULL
            OR (
                btrim(audit_signature_key) <> ''
                AND octet_length(audit_signature_sha256) = 32
            )
        )
    );

-- +goose Down
ALTER TABLE documents
    DROP CONSTRAINT IF EXISTS documents_audit_payload_evidence_pair_chk,
    DROP CONSTRAINT IF EXISTS documents_audit_signature_evidence_pair_chk,
    DROP COLUMN IF EXISTS audit_payload_key,
    DROP COLUMN IF EXISTS audit_payload_sha256,
    DROP COLUMN IF EXISTS audit_signature_key,
    DROP COLUMN IF EXISTS audit_signature_sha256;
