-- name: EnqueueEmailDelivery :one
INSERT INTO email_deliveries (to_email, subject, html_body, text_body, reply_to, from_name, headers_json)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: ClaimDueEmailDeliveries :many
-- Atomically lease a batch before SMTP I/O. Multiple workers use SKIP LOCKED,
-- and the five-minute next_attempt_at lease keeps a claimed row invisible to
-- peers while allowing recovery if a worker crashes after claiming it. SMTP is
-- separately capped at 30 seconds, well inside the lease.
WITH due AS (
  SELECT id
  FROM email_deliveries
  WHERE status IN ('pending', 'retrying')
    AND next_attempt_at <= now()
  ORDER BY next_attempt_at
  FOR UPDATE SKIP LOCKED
  LIMIT $1
)
UPDATE email_deliveries d
SET status = 'retrying',
    next_attempt_at = now() + interval '5 minutes'
FROM due
WHERE d.id = due.id
RETURNING d.*;

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
