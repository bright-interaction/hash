-- name: CreateOrg :one
INSERT INTO orgs (name, plan)
VALUES ($1, $2)
RETURNING *;

-- name: GetOrg :one
SELECT * FROM orgs WHERE id = $1;

-- name: SetOrgChangeApprovalMode :one
UPDATE orgs SET change_approval_mode = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: CreateUser :one
INSERT INTO users (org_id, email, name, role, zitadel_sub)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByZitadelSub :one
SELECT * FROM users WHERE zitadel_sub = $1;

-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: ListUsersByOrg :many
SELECT * FROM users WHERE org_id = $1 ORDER BY created_at DESC;

-- name: UpdateUserRole :one
UPDATE users SET role = $3 WHERE id = $1 AND org_id = $2 RETURNING *;

-- name: CountOrgOwners :one
SELECT COUNT(*) FROM users WHERE org_id = $1 AND role = 'owner';

-- name: CreateAPIKey :one
INSERT INTO api_keys (org_id, user_id, key_prefix, key_hash, name, scopes, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetAPIKeyByPrefix :one
SELECT * FROM api_keys
WHERE key_prefix = $1
  AND (expires_at IS NULL OR expires_at > now());

-- name: TouchAPIKey :exec
UPDATE api_keys SET last_used_at = now() WHERE id = $1;

-- name: ListAPIKeysByUser :many
SELECT id, org_id, user_id, key_prefix, name, scopes, expires_at, last_used_at, created_at
FROM api_keys
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: DeleteAPIKey :exec
DELETE FROM api_keys WHERE id = $1 AND user_id = $2;
