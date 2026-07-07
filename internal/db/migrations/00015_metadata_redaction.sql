-- +goose Up

-- Phase 8.7: per-document record of what metadata the sanitizer stripped
-- when blobs were uploaded. Surfaced inside the audit cert so signers + a
-- court reviewer can see the doc was GDPR-cleaned: PDF /Info, XMP, embedded
-- JavaScript, EXIF/GPS, ICC profiles, edit history.
--
-- The column lives directly on documents so the existing audit-cert
-- renderer can read it without joining another table. JSONB shape:
--
--   {
--     "schema_version": 1,
--     "items": [
--       { "asset": "template-pdf", "method": "pdfcpu", "stripped": ["author","xmp","javascript"], "bytes_before": 12345, "bytes_after": 11111 },
--       { "asset": "logo",         "method": "image-reencode", "stripped": ["exif","gps","icc"], "bytes_before": ..., "bytes_after": ... }
--     ]
--   }

ALTER TABLE documents
    ADD COLUMN metadata_redaction_report JSONB NOT NULL DEFAULT '{}'::jsonb;

-- +goose Down

ALTER TABLE documents DROP COLUMN metadata_redaction_report;
