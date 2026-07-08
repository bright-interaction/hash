-- name: CreateField :one
INSERT INTO document_fields (document_id, recipient_id, type, page, x_pct, y_pct, w_pct, h_pct, required, label, options_json)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: ListFieldsByDocument :many
SELECT * FROM document_fields
WHERE document_id = $1
ORDER BY page, y_pct, x_pct;

-- name: ListFieldsByRecipient :many
SELECT * FROM document_fields
WHERE document_id = $1
  AND (recipient_id = $2 OR recipient_id IS NULL)
ORDER BY page, y_pct, x_pct;

-- name: UpdateFieldValue :one
-- Scoped by document_id AND gated on the parent document still being active, so a
-- field can only be filled on the doc it belongs to and never on a terminal
-- (voided/completed/declined/expired) legal record, even under a void-mid-submit race.
UPDATE document_fields
SET value = $3, completed_at = now()
WHERE document_fields.id = $1
  AND document_fields.document_id = $2
  AND EXISTS (
    SELECT 1 FROM documents d
    WHERE d.id = document_fields.document_id AND d.status IN ('sent', 'in_progress')
  )
RETURNING *;

-- name: DeleteFieldByID :exec
DELETE FROM document_fields
WHERE document_fields.id = $1
  AND document_fields.document_id IN (SELECT documents.id FROM documents WHERE documents.org_id = $2);

-- name: CountUnfilledRequiredForRecipient :one
SELECT COUNT(*) FROM document_fields
WHERE document_id = $1
  AND recipient_id = $2
  AND required = TRUE
  AND type IN ('text','date','checkbox','dropdown','initial')
  AND (value IS NULL OR value = '');


-- name: GetFieldOwnerDoc :one
-- The owning document of a fillable field, org-scoped. Used to enforce doc-scope
-- on delete_document_field so a doc-scoped token cannot delete a sibling doc's field.
SELECT document_fields.document_id
FROM document_fields
JOIN documents ON documents.id = document_fields.document_id
WHERE document_fields.id = $1 AND documents.org_id = $2;
