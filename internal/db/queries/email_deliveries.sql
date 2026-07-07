-- name: EnqueueEmailDelivery :one
INSERT INTO email_deliveries (to_email, subject, html_body, text_body, reply_to, from_name, headers_json)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: ListDueEmailDeliveries :many
SELECT * FROM email_deliveries
WHERE status IN ('pending', 'retrying')
  AND next_attempt_at <= now()
ORDER BY next_attempt_at
LIMIT $1;

-- name: MarkEmailDeliverySent :exec
UPDATE email_deliveries
SET status = 'sent', sent_at = now(), last_error = ''
WHERE id = $1;

-- name: MarkEmailDeliveryRetrying :exec
UPDATE email_deliveries
SET status = 'retrying',
    attempts = attempts + 1,
    last_error = $2,
    next_attempt_at = $3
WHERE id = $1;

-- name: MarkEmailDeliveryFailed :exec
UPDATE email_deliveries
SET status = 'failed',
    attempts = attempts + 1,
    last_error = $2
WHERE id = $1;
