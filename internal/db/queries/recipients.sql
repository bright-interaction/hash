-- name: CreateRecipient :one
INSERT INTO recipients (document_id, role, email, name, order_index, magic_token_hash, magic_token_expires_at, locale)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: RotateRecipientMagicToken :exec
UPDATE recipients
SET magic_token_hash       = $3,
    magic_token_expires_at = $4
WHERE id = $1 AND document_id = $2;

-- name: GetRecipient :one
SELECT r.* FROM recipients r
JOIN documents d ON d.id = r.document_id
WHERE r.id = $1 AND d.org_id = $2;

-- name: GetRecipientByTokenHash :one
SELECT r.*, d.org_id AS doc_org_id, d.status AS doc_status
FROM recipients r
JOIN documents d ON d.id = r.document_id
WHERE r.magic_token_hash = $1;

-- name: ListRecipientsByDocument :many
SELECT * FROM recipients
WHERE document_id = $1
ORDER BY order_index, created_at;

-- name: UpdateRecipient :one
UPDATE recipients
SET email = $3,
    name = $4,
    role = $5,
    order_index = $6,
    locale = $7
WHERE id = $1 AND document_id = $2
RETURNING *;

-- name: SetRecipientStatus :exec
-- Status precondition: a recipient already in a terminal state (signed or
-- declined) cannot be transitioned again, so an already-signed signer can't
-- self-downgrade to declined and a stale double-write is a no-op. Safe for
-- the viewed/sent callers (their current status is never signed/declined).
UPDATE recipients
SET status = $3,
    sent_at = CASE WHEN $3 = 'sent' THEN now() ELSE sent_at END,
    first_viewed_at = CASE WHEN $3 = 'viewed' AND first_viewed_at IS NULL THEN now() ELSE first_viewed_at END,
    signed_at = CASE WHEN $3 = 'signed' THEN now() ELSE signed_at END,
    declined_reason = CASE WHEN $3 = 'declined' THEN $4 ELSE declined_reason END
WHERE id = $1 AND document_id = $2
  AND status NOT IN ('signed','declined');

-- name: InvalidateRecipientTokens :exec
-- Expire every magic link for a document the moment it reaches a terminal
-- state (completed/declined/voided/expired). Defense-in-depth alongside the
-- doc-status gates in the signing engine so a still-live link can never drive
-- a terminal-state mutation.
UPDATE recipients
SET magic_token_expires_at = now()
WHERE document_id = $1;

-- name: DeleteRecipient :exec
DELETE FROM recipients
WHERE id = $1 AND document_id = $2;

-- name: CountUnsignedSigners :one
SELECT COUNT(*) FROM recipients
WHERE document_id = $1
  AND role = 'signer'
  AND status NOT IN ('signed','declined');

-- name: CountUnsignedSignersByRoles :one
-- Completion is data-driven: a document is done when every recipient whose role
-- has a signature field (passed in roles) has signed. Supports multi-party
-- signing (e.g. a client 'signer' plus a provider 'approver' counter-signature).
SELECT COUNT(*) FROM recipients
WHERE document_id = sqlc.arg(document_id)
  AND role = ANY(sqlc.arg(roles)::text[])
  AND status NOT IN ('signed','declined');

-- name: CountPendingAcceptors :one
-- Acknowledgement-mode completion: every non-cc recipient must have accepted (or
-- declined) for the document to complete. cc recipients are informational and
-- never block completion.
SELECT COUNT(*) FROM recipients
WHERE document_id = $1
  AND role <> 'cc'
  AND status NOT IN ('accepted','declined');
