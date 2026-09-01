-- name: CreateWebhookEndpoint :one
INSERT INTO webhook_endpoints (
  id, org_id, url, secret_ref, secret, secret_ciphertext, events_subscribed
)
VALUES ($1, $2, $3, $4, '', $5, $6)
RETURNING id, org_id, url, secret_ref, events_subscribed, active, created_at;

-- name: ListWebhookEndpointsByOrg :many
SELECT id, url, events_subscribed, active, created_at
FROM webhook_endpoints
WHERE org_id = $1
ORDER BY created_at DESC;

-- name: ListActiveWebhookEndpointsForEvent :many
SELECT id FROM webhook_endpoints
WHERE org_id = $1
  AND active = TRUE
  AND sqlc.arg(kind)::text = ANY(events_subscribed);

-- name: DeleteWebhookEndpoint :one
DELETE FROM webhook_endpoints WHERE id = $1 AND org_id = $2
RETURNING id;

-- name: EnqueueWebhookDelivery :one
INSERT INTO webhook_deliveries (endpoint_id, event_id, status, next_attempt_at)
VALUES ($1, $2, 'pending', now())
ON CONFLICT (endpoint_id, event_id) DO UPDATE
SET event_id = EXCLUDED.event_id
RETURNING *;

-- name: ReconcileMissingWebhookDeliveries :execrows
-- The immediate audit hook is latency optimization, not the durability
-- boundary. Reconstruct any delivery row lost between the committed event and
-- post-commit fan-out. An endpoint only receives events created after that
-- endpoint existed; the unique index makes this safe under multiple workers.
WITH candidates AS (
  SELECT ep.id AS endpoint_id, ev.id AS event_id
  FROM events ev
  JOIN webhook_endpoints ep
    ON ep.org_id = ev.org_id
   AND ep.active = TRUE
   AND ev.kind = ANY(ep.events_subscribed)
   AND ep.created_at <= ev.created_at
  WHERE NOT EXISTS (
    SELECT 1
    FROM webhook_deliveries d
    WHERE d.endpoint_id = ep.id
      AND d.event_id = ev.id
  )
  ORDER BY ev.created_at, ev.id, ep.id
  LIMIT $1
)
INSERT INTO webhook_deliveries (endpoint_id, event_id, status, next_attempt_at)
SELECT endpoint_id, event_id, 'pending', now()
FROM candidates
ON CONFLICT (endpoint_id, event_id) DO NOTHING;

-- name: ClaimDueWebhookDeliveries :many
-- Atomically lease a batch before outbound HTTP I/O. Multiple workers use
-- SKIP LOCKED, and the five-minute next_attempt_at lease keeps a claimed row
-- invisible to peers while allowing recovery if a worker crashes. Dispatch is
-- separately capped at 15 seconds, well inside the lease.
WITH due AS (
  SELECT id
  FROM webhook_deliveries
  WHERE status IN ('pending','retrying')
    AND next_attempt_at <= now()
  ORDER BY next_attempt_at
  FOR UPDATE SKIP LOCKED
  LIMIT $1
)
UPDATE webhook_deliveries d
SET status = 'retrying',
    next_attempt_at = now() + interval '5 minutes',
    updated_at = now()
FROM due
WHERE d.id = due.id
RETURNING d.*;

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
