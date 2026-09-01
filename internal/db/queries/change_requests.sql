-- name: CreateChangeRequest :one
INSERT INTO change_requests (document_id, recipient_id, message, block_id, quote, context, proposed)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetChangeRequest :one
SELECT cr.* FROM change_requests cr
JOIN documents d ON d.id = cr.document_id
WHERE cr.id = $1 AND d.org_id = $2;

-- name: GetChangeRequestForUpdate :one
-- ResolveChange holds the parent document lock first, then claims the request.
-- This prevents two approve/deny calls from both observing an open request and
-- ensures auto-apply + resolution commit (or roll back) together.
SELECT cr.* FROM change_requests cr
JOIN documents d ON d.id = cr.document_id
WHERE cr.id = $1 AND d.org_id = $2
FOR UPDATE OF cr;

-- name: ResolveChangeRequest :one
-- Approve or deny a single inline change request.
UPDATE change_requests
SET status = 'resolved', resolution = $3, resolved_at = now()
WHERE id = $1 AND document_id = $2 AND status = 'open'
RETURNING *;

-- name: CountOpenChangeRequests :one
SELECT COUNT(*) FROM change_requests WHERE document_id = $1 AND status = 'open';

-- name: ListChangeRequests :many
SELECT cr.*, r.name AS recipient_name, r.email AS recipient_email
FROM change_requests cr
LEFT JOIN recipients r ON r.id = cr.recipient_id
WHERE cr.document_id = $1
ORDER BY cr.created_at DESC;

-- name: ResolveChangeRequests :exec
-- Mark every open request on a document resolved (called when the sender
-- revises the document into a new draft).
UPDATE change_requests
SET status = 'resolved', resolved_at = now()
WHERE document_id = $1 AND status = 'open';

-- name: ResetRecipientsForRevision :exec
-- Reset only recipients who have never produced legal evidence. Revise checks
-- the whole ceremony first; this predicate is a second DB-level defense so a
-- future caller can never erase a signature/acceptance timestamp in place.
UPDATE recipients
SET status = 'pending', signed_at = NULL
WHERE document_id = $1
  AND status NOT IN ('declined','signed','accepted')
  AND signed_at IS NULL;
