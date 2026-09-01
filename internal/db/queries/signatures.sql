-- name: InsertSignature :one
-- One signature per recipient per document (uq_signatures_document_recipient).
-- A concurrent double-POST that races past the in-memory status check hits the
-- conflict and DO NOTHING returns no row (pgx.ErrNoRows), which the engine
-- treats as "already signed" rather than inserting a duplicate.
INSERT INTO signatures (
    document_id, recipient_id, field_id, font, typed_name,
    image_storage_key, image_sha256, image_version_id,
    signer_ip, signer_ua
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (document_id, recipient_id) DO NOTHING
RETURNING *;

-- name: ListSignaturesByDocument :many
SELECT * FROM signatures
WHERE document_id = $1
ORDER BY signed_at;

-- name: PinLegacySignatureVersion :one
UPDATE signatures
SET image_version_id = sqlc.arg(image_version_id),
    image_version_pin_required = TRUE
WHERE id = sqlc.arg(id)
  AND document_id = sqlc.arg(document_id)
  AND image_version_pin_required = FALSE
  AND image_version_id IS NULL
RETURNING *;
