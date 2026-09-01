-- name: UpsertVariableBinding :one
INSERT INTO document_variable_bindings (
    document_id, variable_name, source_kind, source_ref, source_path, fallback
) VALUES (
    $1, $2, $3, $4, $5, $6
)
ON CONFLICT (document_id, variable_name) DO UPDATE SET
    source_kind = EXCLUDED.source_kind,
    source_ref  = EXCLUDED.source_ref,
    source_path = EXCLUDED.source_path,
    fallback    = EXCLUDED.fallback,
    updated_at  = now()
RETURNING *;

-- name: ListVariableBindings :many
SELECT * FROM document_variable_bindings
WHERE document_id = $1
ORDER BY variable_name ASC;

-- name: ListOrgIDsForVariableSource :many
-- Resolve an inbound integration event to the tenant ledgers it affects. The
-- webhook handler audits once per matching org before invalidating its
-- process-local resolver cache; a zero-org result is a genuine no-op.
SELECT DISTINCT d.org_id
FROM document_variable_bindings AS b
JOIN documents AS d ON d.id = b.document_id
WHERE b.source_kind = $1
  AND b.source_ref = $2
  -- Only draft documents ever fetch live bindings. Sent/final/deleted rows use
  -- their frozen values and must not cause indefinite inbound audit traffic.
  AND d.status = 'draft'
  AND d.deleted_at IS NULL
ORDER BY d.org_id;

-- name: PurgeExpiredBrightCRMWebhookReceipts :execrows
-- Opportunistically bound the replay inbox without letting one request spend
-- unbounded time deleting a long-neglected backlog.
WITH expired AS (
    SELECT delivery_correlation
    FROM brightcrm_webhook_receipts
    WHERE expires_at <= now()
    ORDER BY expires_at, delivery_correlation
    LIMIT 1000
    FOR UPDATE SKIP LOCKED
)
DELETE FROM brightcrm_webhook_receipts AS receipts
USING expired
WHERE receipts.delivery_correlation = expired.delivery_correlation;

-- name: ClaimBrightCRMWebhookReceipt :execrows
INSERT INTO brightcrm_webhook_receipts (
    delivery_correlation, payload_correlation, org_ids
) VALUES (
    sqlc.arg(delivery_correlation), sqlc.arg(payload_correlation), sqlc.arg(org_ids)
)
ON CONFLICT (delivery_correlation) DO NOTHING;

-- name: GetBrightCRMWebhookReceipt :one
SELECT payload_correlation, org_ids
FROM brightcrm_webhook_receipts
WHERE delivery_correlation = $1;

-- name: DeleteVariableBinding :exec
DELETE FROM document_variable_bindings
WHERE document_id = $1 AND variable_name = $2;

-- name: UpdateVariableBindingResolved :exec
UPDATE document_variable_bindings
   SET last_value    = $3,
       last_resolved = now(),
       last_error    = '',
       updated_at    = now()
 WHERE document_id = $1 AND variable_name = $2;

-- name: UpdateVariableBindingError :exec
UPDATE document_variable_bindings
   SET last_error    = $3,
       last_resolved = now(),
       updated_at    = now()
 WHERE document_id = $1 AND variable_name = $2;
