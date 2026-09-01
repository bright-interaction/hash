-- name: CreateOrg :one
INSERT INTO orgs (name, plan)
VALUES ($1, $2)
RETURNING *;

-- name: GetOrg :one
SELECT * FROM orgs WHERE id = $1;

-- name: ListOrgIDsAfter :many
-- Keyset page used by release-blocking estate integrity checks. A zero UUID is
-- the initial cursor; application org IDs are generated randomly and nonzero.
SELECT id FROM orgs
WHERE id > $1
ORDER BY id ASC
LIMIT $2;

-- name: SetOrgChangeApprovalMode :one
UPDATE orgs SET change_approval_mode = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: CreateUser :one
INSERT INTO users (org_id, email, name, role, zitadel_sub)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE lower(email) = lower($1);

-- name: GetUserByZitadelSub :one
SELECT * FROM users WHERE zitadel_sub = $1;

-- name: BindUserZitadelSub :one
-- First verified-email login binds an invited/legacy row to one stable OIDC
-- subject. A different subject can never replace that binding merely by later
-- presenting the same (possibly recycled) verified email address.
UPDATE users
SET zitadel_sub = $2
WHERE id = $1
  AND (zitadel_sub IS NULL OR zitadel_sub = $2)
RETURNING *;

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

-- name: ClaimAPIKeyUse :one
-- Make the post-secret-verification authorization point linearizable with
-- deletion and expiry. A request whose key was deleted or expired after the
-- prefix lookup must not enter the handler.
UPDATE api_keys
SET last_used_at = now()
WHERE id = $1
  AND (expires_at IS NULL OR expires_at > now())
RETURNING id;

-- name: ListAPIKeysByUser :many
SELECT id, org_id, user_id, key_prefix, name, scopes, expires_at, last_used_at, created_at
FROM api_keys
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: DeleteAPIKey :one
DELETE FROM api_keys WHERE id = $1 AND user_id = $2
RETURNING id;
