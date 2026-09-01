-- name: CreateField :one
-- Internal signing primitive. The sign engine materialises block-authored
-- signature fields after send, so authoring surfaces must use
-- CreateDraftField instead of this query.
INSERT INTO document_fields (document_id, recipient_id, type, page, x_pct, y_pct, w_pct, h_pct, required, label, options_json)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: CreateDraftField :one
-- Atomic authoring guard: a stale REST/MCP draft read cannot add a field after
-- send. If assigned, the recipient must belong to the same document.
WITH draft_document AS MATERIALIZED (
  SELECT d.id
  FROM documents d
  WHERE d.id = sqlc.arg(document_id)
    AND d.status = 'draft'
  FOR UPDATE
)
INSERT INTO document_fields (document_id, recipient_id, type, page, x_pct, y_pct, w_pct, h_pct, required, label, options_json)
SELECT d.id, sqlc.arg(recipient_id), sqlc.arg(type), sqlc.arg(page),
       sqlc.arg(x_pct), sqlc.arg(y_pct), sqlc.arg(w_pct), sqlc.arg(h_pct),
       sqlc.arg(required), sqlc.arg(label), sqlc.arg(options_json)
FROM draft_document d
WHERE (
    sqlc.arg(recipient_id)::uuid IS NULL
    OR EXISTS (
      SELECT 1
      FROM recipients r
      WHERE r.id = sqlc.arg(recipient_id)::uuid
        AND r.document_id = d.id
    )
  )
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
-- Scoped by document, field ownership, active parent, and a recipient who has
-- not already signed/accepted/declined. The recipient status predicate prevents
-- a signer from changing the final contract while another role is still pending.
UPDATE document_fields
SET value = $3, completed_at = now()
WHERE document_fields.id = $1
  AND document_fields.document_id = $2
  AND (document_fields.recipient_id = $4 OR document_fields.recipient_id IS NULL)
  AND EXISTS (
    SELECT 1 FROM documents d
    WHERE d.id = document_fields.document_id AND d.status IN ('sent', 'in_progress')
  )
  AND EXISTS (
    SELECT 1 FROM recipients r
    WHERE r.id = $4
      AND r.document_id = document_fields.document_id
      AND r.status IN ('pending','sent','viewed')
  )
RETURNING *;

-- name: DeleteFieldByID :one
-- Keep the state check in the destructive statement. document_fields is the
-- parent of signatures, so deleting a field after send would cascade-delete
-- legal evidence.
WITH draft_document AS MATERIALIZED (
  SELECT d.id
  FROM documents d
  JOIN document_fields candidate ON candidate.document_id = d.id
  WHERE candidate.id = sqlc.arg(id)
    AND d.org_id = sqlc.arg(org_id)
    AND d.status = 'draft'
  FOR UPDATE
)
DELETE FROM document_fields f
USING draft_document d
WHERE f.id = sqlc.arg(id)
  AND d.id = f.document_id
RETURNING f.id;

-- name: CountUnfilledRequiredForRecipient :one
SELECT COUNT(*) FROM document_fields
WHERE document_id = $1
  -- Signer field APIs deliberately expose unassigned fields to the active
  -- signer. The terminal Sign gate must count the same set or a direct client
  -- can skip a required "any recipient" value and still complete.
  AND (recipient_id = $2 OR recipient_id IS NULL)
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
