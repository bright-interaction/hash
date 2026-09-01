-- name: InsertEvent :one
-- created_at and payload_hashed are supplied explicitly (not DB-defaulted) so
-- the row_hash, which now binds created_at and the exact payload bytes, is
-- reproducible by the verifier. payload_hashed stores the byte-exact hashed
-- input; payload_json keeps the JSONB copy for the timeline UI.
INSERT INTO events (org_id, document_id, recipient_id, actor_user_id, kind, ip, ua, payload_json, payload_hashed, prev_hash, row_hash, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING *;

-- name: AcquireOrgChainLock :exec
-- Per-org transaction-scoped advisory lock so concurrent audit.Log calls for
-- the same org serialize their read-head + insert (preventing chain forks).
-- Auto-released at commit/rollback. Different orgs use different lock keys so
-- cross-org concurrency is unaffected.
SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0));

-- name: LatestEventChainHeadForOrg :one
-- Return the timestamp with the hash so multiple LogTx appends in one caller
-- transaction can assign strictly increasing microsecond timestamps. Ordering
-- the chain by created_at then id is only deterministic when a newly appended
-- row cannot tie its predecessor's timestamp.
SELECT row_hash, created_at FROM events
WHERE org_id = $1 AND row_hash IS NOT NULL
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: ListChainedEventsForOrg :many
SELECT id, org_id, document_id, recipient_id, actor_user_id, kind, ip, ua, payload_json, payload_hashed, prev_hash, row_hash, created_at
FROM events
WHERE org_id = $1
ORDER BY created_at ASC, id ASC
LIMIT $2;

-- name: ListChainedEventsPageForOrg :many
-- Keyset pagination lets the chain verifier cover the entire immutable ledger
-- without either loading it all into memory or silently treating a LIMITed
-- prefix as a successful full verification.
SELECT *
FROM events
WHERE org_id = $1
  AND (
    sqlc.narg(after_created_at)::timestamptz IS NULL
    OR created_at > sqlc.narg(after_created_at)::timestamptz
    OR (
      created_at = sqlc.narg(after_created_at)::timestamptz
      AND id > sqlc.narg(after_id)::uuid
    )
  )
ORDER BY created_at ASC, id ASC
LIMIT sqlc.arg(page_limit);

-- name: GetEventByID :one
SELECT * FROM events WHERE id = $1;

-- name: ListEventsByDocument :many
SELECT * FROM events
WHERE document_id = $1
ORDER BY created_at DESC, id DESC
LIMIT $2;

-- name: ListEventsByDocumentChronological :many
-- Evidence certificates commit to the exact pre-final document subset. Read
-- the oldest signed count directly so later completion/reminder/export events
-- cannot displace a ceremony row from a DESC/LIMIT window.
SELECT * FROM events
WHERE document_id = $1
ORDER BY created_at ASC, id ASC
LIMIT $2;

-- name: ListRecentEventsByOrg :many
SELECT * FROM events
WHERE org_id = $1
ORDER BY created_at DESC
LIMIT $2;
