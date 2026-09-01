-- +goose Up
-- Pin every legal S3 object to the exact VersionId returned by PutObject.
-- Object Lock protects versions, not logical keys: a writer can add arbitrary
-- newer shadow versions. Digest-only history search is therefore retained only
-- as a one-time migration path for rows created before this schema.

ALTER TABLE templates
    ADD COLUMN pdf_storage_version_id TEXT,
    ADD COLUMN evidence_version_pin_required BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE templates
    ALTER COLUMN evidence_version_pin_required SET DEFAULT TRUE,
    ADD CONSTRAINT templates_pdf_version_id_nonempty CHECK (
        pdf_storage_version_id IS NULL OR
        (btrim(pdf_storage_version_id) <> '' AND octet_length(pdf_storage_version_id) <= 1024)
    ),
    ADD CONSTRAINT templates_required_pdf_version_pinned CHECK (
        NOT evidence_version_pin_required OR
        pdf_storage_key IS NULL OR (
            pdf_storage_version_id IS NOT NULL AND
            pdf_sha256 IS NOT NULL AND octet_length(pdf_sha256) = 32
        )
    );

ALTER TABLE documents
    ADD COLUMN pdf_storage_version_id TEXT,
    ADD COLUMN rendered_pdf_version_id TEXT,
    ADD COLUMN final_pdf_version_id TEXT,
    ADD COLUMN audit_cert_sha256 BYTEA,
    ADD COLUMN audit_cert_version_id TEXT,
    ADD COLUMN audit_payload_version_id TEXT,
    ADD COLUMN audit_signature_version_id TEXT,
    -- Existing rows are explicitly legacy. New rows default to pinned and are
    -- rejected if a referenced legal object lacks its exact version identity.
    ADD COLUMN evidence_version_pins_required BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE documents
    ALTER COLUMN evidence_version_pins_required SET DEFAULT TRUE,
    ADD CONSTRAINT documents_legal_version_ids_nonempty CHECK (
        (pdf_storage_version_id IS NULL OR (btrim(pdf_storage_version_id) <> '' AND octet_length(pdf_storage_version_id) <= 1024)) AND
        (rendered_pdf_version_id IS NULL OR (btrim(rendered_pdf_version_id) <> '' AND octet_length(rendered_pdf_version_id) <= 1024)) AND
        (final_pdf_version_id IS NULL OR (btrim(final_pdf_version_id) <> '' AND octet_length(final_pdf_version_id) <= 1024)) AND
        (audit_cert_version_id IS NULL OR (btrim(audit_cert_version_id) <> '' AND octet_length(audit_cert_version_id) <= 1024)) AND
        (audit_payload_version_id IS NULL OR (btrim(audit_payload_version_id) <> '' AND octet_length(audit_payload_version_id) <= 1024)) AND
        (audit_signature_version_id IS NULL OR (btrim(audit_signature_version_id) <> '' AND octet_length(audit_signature_version_id) <= 1024))
    ),
    ADD CONSTRAINT documents_audit_cert_digest_valid CHECK (
        audit_cert_sha256 IS NULL OR octet_length(audit_cert_sha256) = 32
    ),
    ADD CONSTRAINT documents_required_legal_versions_pinned CHECK (
        NOT evidence_version_pins_required OR (
            (pdf_storage_key IS NULL OR (
                pdf_storage_version_id IS NOT NULL AND
                pdf_sha256 IS NOT NULL AND octet_length(pdf_sha256) = 32
            )) AND
            (rendered_pdf_key IS NULL OR (
                rendered_pdf_version_id IS NOT NULL AND
                rendered_pdf_sha IS NOT NULL AND octet_length(rendered_pdf_sha) = 32
            )) AND
            (final_pdf_key IS NULL OR (
                final_pdf_version_id IS NOT NULL AND
                final_pdf_sha IS NOT NULL AND octet_length(final_pdf_sha) = 32
            )) AND
            (audit_cert_key IS NULL OR (
                audit_cert_version_id IS NOT NULL AND
                audit_cert_sha256 IS NOT NULL AND octet_length(audit_cert_sha256) = 32
            )) AND
            (audit_payload_key IS NULL OR audit_payload_version_id IS NOT NULL) AND
            (audit_signature_key IS NULL OR audit_signature_version_id IS NOT NULL)
        )
    );

ALTER TABLE document_finalization_intents
    ADD COLUMN final_pdf_version_id TEXT,
    ADD COLUMN audit_cert_version_id TEXT,
    ADD COLUMN audit_payload_version_id TEXT,
    ADD COLUMN audit_signature_version_id TEXT,
    ADD COLUMN evidence_version_pins_required BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE document_finalization_intents
    ALTER COLUMN evidence_version_pins_required SET DEFAULT TRUE,
    ADD CONSTRAINT finalization_intent_version_ids_nonempty CHECK (
        (final_pdf_version_id IS NULL OR (btrim(final_pdf_version_id) <> '' AND octet_length(final_pdf_version_id) <= 1024)) AND
        (audit_cert_version_id IS NULL OR (btrim(audit_cert_version_id) <> '' AND octet_length(audit_cert_version_id) <= 1024)) AND
        (audit_payload_version_id IS NULL OR (btrim(audit_payload_version_id) <> '' AND octet_length(audit_payload_version_id) <= 1024)) AND
        (audit_signature_version_id IS NULL OR (btrim(audit_signature_version_id) <> '' AND octet_length(audit_signature_version_id) <= 1024))
    ),
    ADD CONSTRAINT finalization_intent_required_versions_pinned CHECK (
        NOT evidence_version_pins_required OR (
            final_pdf_version_id IS NOT NULL AND
            audit_cert_version_id IS NOT NULL AND
            audit_payload_version_id IS NOT NULL AND
            audit_signature_version_id IS NOT NULL
        )
    );

ALTER TABLE signatures
    ADD COLUMN image_version_id TEXT,
    ADD COLUMN image_version_pin_required BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE signatures
    ALTER COLUMN image_version_pin_required SET DEFAULT TRUE,
    ADD CONSTRAINT signatures_image_version_id_nonempty CHECK (
        image_version_id IS NULL OR (btrim(image_version_id) <> '' AND octet_length(image_version_id) <= 1024)
    ),
    ADD CONSTRAINT signatures_required_image_version_pinned CHECK (
        NOT image_version_pin_required OR (
            image_version_id IS NOT NULL AND
            btrim(image_storage_key) <> '' AND
            image_sha256 IS NOT NULL AND octet_length(image_sha256) = 32
        )
    );

-- +goose Down
ALTER TABLE templates
    DROP CONSTRAINT IF EXISTS templates_required_pdf_version_pinned,
    DROP CONSTRAINT IF EXISTS templates_pdf_version_id_nonempty,
    DROP COLUMN IF EXISTS evidence_version_pin_required,
    DROP COLUMN IF EXISTS pdf_storage_version_id;

ALTER TABLE signatures
    DROP CONSTRAINT IF EXISTS signatures_required_image_version_pinned,
    DROP CONSTRAINT IF EXISTS signatures_image_version_id_nonempty,
    DROP COLUMN IF EXISTS image_version_pin_required,
    DROP COLUMN IF EXISTS image_version_id;

ALTER TABLE document_finalization_intents
    DROP CONSTRAINT IF EXISTS finalization_intent_required_versions_pinned,
    DROP CONSTRAINT IF EXISTS finalization_intent_version_ids_nonempty,
    DROP COLUMN IF EXISTS evidence_version_pins_required,
    DROP COLUMN IF EXISTS audit_signature_version_id,
    DROP COLUMN IF EXISTS audit_payload_version_id,
    DROP COLUMN IF EXISTS audit_cert_version_id,
    DROP COLUMN IF EXISTS final_pdf_version_id;

ALTER TABLE documents
    DROP CONSTRAINT IF EXISTS documents_required_legal_versions_pinned,
    DROP CONSTRAINT IF EXISTS documents_audit_cert_digest_valid,
    DROP CONSTRAINT IF EXISTS documents_legal_version_ids_nonempty,
    DROP COLUMN IF EXISTS evidence_version_pins_required,
    DROP COLUMN IF EXISTS audit_signature_version_id,
    DROP COLUMN IF EXISTS audit_payload_version_id,
    DROP COLUMN IF EXISTS audit_cert_version_id,
    DROP COLUMN IF EXISTS audit_cert_sha256,
    DROP COLUMN IF EXISTS final_pdf_version_id,
    DROP COLUMN IF EXISTS rendered_pdf_version_id,
    DROP COLUMN IF EXISTS pdf_storage_version_id;
