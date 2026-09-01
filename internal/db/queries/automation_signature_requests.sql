-- name: LockAutomationSignatureRequestQuota :exec
-- Serialize quota-counting materialization for one organization. Collisions in
-- hashtextextended only reduce concurrency; they cannot cross authorization or
-- data boundaries because every following query remains org-scoped.
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(org_id)::text, 63001));

-- name: ClaimAutomationSignatureRequest :one
INSERT INTO automation_signature_requests (
    org_id, idempotency_key_hash, request_hash
)
VALUES ($1, $2, $3)
ON CONFLICT (org_id, idempotency_key_hash) DO NOTHING
RETURNING *;

-- name: GetAutomationSignatureRequestForUpdate :one
SELECT *
FROM automation_signature_requests
WHERE org_id = $1 AND idempotency_key_hash = $2
FOR UPDATE;

-- name: BindAutomationSignatureRequestDocument :one
UPDATE automation_signature_requests
SET document_id = $3,
    state = 'ready',
    updated_at = now()
WHERE id = $1
  AND org_id = $2
  AND state = 'claimed'
  AND document_id IS NULL
RETURNING *;

-- name: MarkAutomationSignatureRequestSent :execrows
UPDATE automation_signature_requests
SET state = 'sent',
    updated_at = now()
WHERE id = $1
  AND org_id = $2
  AND document_id = $3
  AND state IN ('ready', 'sent');

-- name: GetAutomationSignatureRequest :one
SELECT *
FROM automation_signature_requests
WHERE id = $1 AND org_id = $2;

-- name: GetAutomationSignatureRequestIDByDocument :one
-- Lifecycle webhooks use this durable Hash-owned identifier to correlate an
-- event with the original automation command without retaining or disclosing
-- the producer's raw idempotency key.
SELECT id
FROM automation_signature_requests
WHERE org_id = $1
  AND document_id = $2
ORDER BY created_at
LIMIT 1;
