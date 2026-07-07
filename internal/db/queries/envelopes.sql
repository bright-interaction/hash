-- name: ListEnvelopeChildren :many
SELECT * FROM documents
WHERE parent_envelope_id = $1 AND org_id = $2
ORDER BY envelope_position ASC NULLS LAST, created_at ASC;

-- name: AttachToEnvelope :one
UPDATE documents
   SET parent_envelope_id = $2,
       envelope_position  = $3,
       updated_at         = now()
 WHERE id = $1 AND org_id = $4
   AND is_envelope = FALSE
RETURNING *;

-- name: DetachFromEnvelope :one
UPDATE documents
   SET parent_envelope_id = NULL,
       envelope_position  = NULL,
       updated_at         = now()
 WHERE id = $1 AND org_id = $2
RETURNING *;

-- name: ReorderEnvelopeChild :exec
-- org_id is REQUIRED: without it an org-A caller could reorder an org-B envelope's
-- children by supplying their UUIDs (the only envelope mutation that was missing the
-- tenant predicate; reachable cross-tenant via the MCP reorder tool).
UPDATE documents
   SET envelope_position = $3,
       updated_at        = now()
 WHERE id = $1 AND parent_envelope_id = $2 AND org_id = $4;

-- name: MarkAsEnvelope :one
UPDATE documents
   SET is_envelope = TRUE,
       updated_at  = now()
 WHERE id = $1 AND org_id = $2
   AND parent_envelope_id IS NULL
   AND source_kind = 'blocks'
RETURNING *;

-- name: MaxEnvelopePosition :one
SELECT COALESCE(MAX(envelope_position), 0)::int AS max_pos
FROM documents
WHERE parent_envelope_id = $1;
