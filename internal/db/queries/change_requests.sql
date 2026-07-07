-- name: CreateChangeRequest :one
INSERT INTO change_requests (document_id, recipient_id, message, block_id, quote, context, proposed)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetChangeRequest :one
SELECT cr.* FROM change_requests cr
JOIN documents d ON d.id = cr.document_id
WHERE cr.id = $1 AND d.org_id = $2;

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
-- Clear prior signing progress so a revised document re-sends cleanly: every
-- recipient that has not declined returns to pending with no signed timestamp.
UPDATE recipients
SET status = 'pending', signed_at = NULL
WHERE document_id = $1 AND status <> 'declined';

-- name: DeleteSignaturesByDocument :exec
-- A revised document supersedes the old draft, so signatures captured against
-- the previous version are voided.
DELETE FROM signatures WHERE document_id = $1;
