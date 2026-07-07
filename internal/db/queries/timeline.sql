-- name: ListEventsByDocumentFiltered :many
SELECT * FROM events
WHERE document_id = $1
  AND ($2::text[]      IS NULL OR kind = ANY($2::text[]))
  AND ($3::timestamptz IS NULL OR created_at >= $3)
  AND ($4::timestamptz IS NULL OR created_at <= $4)
ORDER BY created_at DESC
LIMIT $5;

-- name: ListOrgActivityFiltered :many
SELECT * FROM events
WHERE org_id = $1
  AND ($2::text[]      IS NULL OR kind = ANY($2::text[]))
  AND ($3::uuid        = '00000000-0000-0000-0000-000000000000'::uuid OR actor_user_id = $3)
  AND ($4::uuid        = '00000000-0000-0000-0000-000000000000'::uuid OR document_id = $4)
  AND ($5::timestamptz IS NULL OR created_at >= $5)
  AND ($6::timestamptz IS NULL OR created_at <= $6)
ORDER BY created_at DESC
LIMIT $7;

-- name: OrgActivityActorLeaderboard :many
SELECT actor_user_id, COUNT(*)::int AS event_count
FROM events
WHERE org_id = $1
  AND actor_user_id IS NOT NULL
  AND created_at >= $2
GROUP BY actor_user_id
ORDER BY event_count DESC
LIMIT $3;
