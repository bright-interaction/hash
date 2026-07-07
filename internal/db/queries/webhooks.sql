-- name: CreateWebhookEndpoint :one
INSERT INTO webhook_endpoints (org_id, url, secret_ref, secret, events_subscribed)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetWebhookEndpointSecret :one
SELECT secret FROM webhook_endpoints WHERE id = $1;

-- name: ListWebhookEndpointsByOrg :many
SELECT * FROM webhook_endpoints
WHERE org_id = $1
ORDER BY created_at DESC;

-- name: ListActiveWebhookEndpointsForEvent :many
SELECT * FROM webhook_endpoints
WHERE org_id = $1
  AND active = TRUE
  AND sqlc.arg(kind)::text = ANY(events_subscribed);

-- name: DeleteWebhookEndpoint :exec
DELETE FROM webhook_endpoints WHERE id = $1 AND org_id = $2;

-- name: EnqueueWebhookDelivery :one
INSERT INTO webhook_deliveries (endpoint_id, event_id, status, next_attempt_at)
VALUES ($1, $2, 'pending', now())
RETURNING *;

-- name: ListPendingDeliveries :many
SELECT * FROM webhook_deliveries
WHERE status IN ('pending','retrying')
  AND next_attempt_at <= now()
ORDER BY next_attempt_at
LIMIT $1;

-- name: MarkDeliveryDelivered :exec
UPDATE webhook_deliveries
SET status = 'delivered', last_status_code = $2, attempts = attempts + 1, updated_at = now()
WHERE id = $1;

-- name: MarkDeliveryRetrying :exec
UPDATE webhook_deliveries
SET status = 'retrying',
    last_status_code = $2,
    last_error = $3,
    next_attempt_at = $4,
    attempts = attempts + 1,
    updated_at = now()
WHERE id = $1;

-- name: MarkDeliveryFailed :exec
UPDATE webhook_deliveries
SET status = 'failed',
    last_status_code = $2,
    last_error = $3,
    attempts = attempts + 1,
    updated_at = now()
WHERE id = $1;

-- name: ListDeliveriesByEndpoint :many
SELECT * FROM webhook_deliveries
WHERE endpoint_id = $1
ORDER BY created_at DESC
LIMIT $2;
