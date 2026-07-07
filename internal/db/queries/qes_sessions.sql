-- name: CreateQESSession :one
INSERT INTO qes_signing_sessions (
    document_id, recipient_id, org_id, provider,
    provider_session_id, redirect_url, callback_secret
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
)
RETURNING *;

-- name: GetQESSession :one
SELECT * FROM qes_signing_sessions WHERE id = $1;

-- name: GetQESSessionByProvider :one
SELECT * FROM qes_signing_sessions
WHERE provider = $1 AND provider_session_id = $2
LIMIT 1;

-- name: ListPendingQESSessionsForRecipient :many
SELECT * FROM qes_signing_sessions
WHERE recipient_id = $1
  AND status IN ('pending','redirected')
  AND expires_at > now()
ORDER BY created_at DESC;

-- name: MarkQESSessionRedirected :exec
UPDATE qes_signing_sessions
SET status = 'redirected'
WHERE id = $1 AND status = 'pending';

-- name: CompleteQESSession :one
UPDATE qes_signing_sessions
SET status = 'completed',
    identity_assertion_json = $2,
    signature_b64 = $3,
    cert_chain_pem = $4,
    completed_at = now()
WHERE id = $1 AND status IN ('pending','redirected')
RETURNING *;

-- name: FailQESSession :exec
UPDATE qes_signing_sessions
SET status = 'failed', failure_reason = $2, completed_at = now()
WHERE id = $1;

-- name: ListCompletedQESSessionsForDocument :many
SELECT * FROM qes_signing_sessions
WHERE document_id = $1
  AND status = 'completed'
  AND cert_chain_pem IS NOT NULL
ORDER BY completed_at DESC;
