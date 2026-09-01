-- name: CreateBlocksTemplate :one
INSERT INTO templates (org_id, name, source_kind, blocks_json, variables_json, created_by)
VALUES ($1, $2, 'blocks', $3, $4, $5)
RETURNING *;

-- name: CreatePDFTemplate :one
INSERT INTO templates (
    org_id, name, source_kind, pdf_storage_key, pdf_sha256,
    pdf_storage_version_id, evidence_version_pin_required,
    page_count, fields_json, created_by
)
VALUES ($1, $2, 'pdf', $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetTemplate :one
SELECT * FROM templates WHERE id = $1 AND org_id = $2 AND archived_at IS NULL;

-- name: ListTemplates :many
SELECT * FROM templates
WHERE org_id = $1 AND archived_at IS NULL
ORDER BY updated_at DESC
LIMIT $2 OFFSET $3;

-- name: CountTemplates :one
SELECT COUNT(*) FROM templates WHERE org_id = $1 AND archived_at IS NULL;

-- name: UpdateBlocksTemplate :one
UPDATE templates
SET name = $3,
    blocks_json = $4,
    variables_json = $5,
    version = version + 1,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND source_kind = 'blocks' AND archived_at IS NULL
RETURNING *;

-- name: UpdatePDFTemplateFields :one
UPDATE templates
SET fields_json = $3,
    version = version + 1,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND source_kind = 'pdf' AND archived_at IS NULL
RETURNING *;

-- name: ArchiveTemplate :exec
UPDATE templates
SET archived_at = now(), updated_at = now()
WHERE id = $1 AND org_id = $2 AND archived_at IS NULL;
