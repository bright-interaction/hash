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

-- name: ClaimDocAgentTokenUse :one
-- This guarded UPDATE is the authorization boundary for a document-scoped
-- token. Lookup happens before the secret hash comparison, so it must never
-- consume a use. Once the secret has been verified, this statement atomically
-- re-checks revocation, expiry, and max_uses while incrementing used_count.
-- Concurrent requests for a max_uses=1 token therefore cannot both proceed.
UPDATE document_agent_tokens
   SET used_count   = used_count + 1,
       last_used_at = now()
 WHERE id = $1
   AND revoked_at IS NULL
   AND expires_at > now()
   AND (max_uses = 0 OR used_count < max_uses)
RETURNING id;
