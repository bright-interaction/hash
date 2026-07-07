-- name: InsertDocAgentToken :one
INSERT INTO document_agent_tokens (
    document_id, org_id, name, prefix, key_hash, scopes,
    created_by, expires_at, max_uses
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
) RETURNING *;

-- name: GetDocAgentTokenByPrefix :one
SELECT * FROM document_agent_tokens WHERE prefix = $1;

-- name: ListDocAgentTokens :many
SELECT * FROM document_agent_tokens
WHERE document_id = $1 AND org_id = $2
ORDER BY created_at DESC;

-- name: RevokeDocAgentToken :one
UPDATE document_agent_tokens
   SET revoked_at = now()
 WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL
RETURNING *;

-- name: TouchDocAgentToken :exec
UPDATE document_agent_tokens
   SET used_count   = used_count + 1,
       last_used_at = now()
 WHERE id = $1;
