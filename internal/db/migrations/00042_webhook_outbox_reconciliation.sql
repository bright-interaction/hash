-- +goose Up
-- Audit events are the durable source of truth. Fan-out is normally triggered
-- immediately after commit, but a process crash can occur before its delivery
-- rows are inserted. Make endpoint/event idempotency explicit so the worker can
-- safely reconcile that crash window forever.
WITH ranked AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY endpoint_id, event_id
               ORDER BY CASE status
                            WHEN 'delivered' THEN 0
                            WHEN 'pending' THEN 1
                            WHEN 'retrying' THEN 2
                            ELSE 3
                        END,
                        created_at,
                        id
           ) AS duplicate_no
      FROM webhook_deliveries
)
DELETE FROM webhook_deliveries d
USING ranked r
WHERE d.id = r.id
  AND r.duplicate_no > 1;

CREATE UNIQUE INDEX webhook_deliveries_endpoint_event_unique
    ON webhook_deliveries (endpoint_id, event_id);

-- +goose Down
DROP INDEX IF EXISTS webhook_deliveries_endpoint_event_unique;
