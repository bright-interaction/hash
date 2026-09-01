-- name: CreateRecipient :one
WITH draft_document AS MATERIALIZED (
  SELECT d.id
  FROM documents d
  WHERE d.id = sqlc.arg(document_id)
    AND d.status = 'draft'
  FOR UPDATE
)
INSERT INTO recipients (document_id, role, email, name, order_index, magic_token_hash, magic_token_expires_at, locale)
SELECT d.id, sqlc.arg(role), sqlc.arg(email), sqlc.arg(name),
       sqlc.arg(order_index), sqlc.arg(magic_token_hash),
       sqlc.arg(magic_token_expires_at), sqlc.arg(locale)
FROM draft_document d
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
WITH draft_document AS MATERIALIZED (
  SELECT d.id
  FROM documents d
  WHERE d.id = sqlc.arg(document_id)
    AND d.status = 'draft'
  FOR UPDATE
)
UPDATE recipients r
SET email = sqlc.arg(email),
    name = sqlc.arg(name),
    role = sqlc.arg(role),
    order_index = sqlc.arg(order_index),
    locale = sqlc.arg(locale)
FROM draft_document d
WHERE r.id = sqlc.arg(id)
  AND r.document_id = sqlc.arg(document_id)
  AND d.id = r.document_id
RETURNING r.*;

-- name: SetRecipientStatus :exec
-- Status precondition: a recipient already in a terminal state (signed,
-- accepted, or declined) cannot be transitioned again. This prevents captured
-- signature/acknowledgement evidence from being self-downgraded by a stale
-- decline/view request; terminal double-writes are no-ops.
UPDATE recipients
SET status = $3,
    sent_at = CASE WHEN $3 = 'sent' THEN now() ELSE sent_at END,
    first_viewed_at = CASE WHEN $3 = 'viewed' AND first_viewed_at IS NULL THEN now() ELSE first_viewed_at END,
    signed_at = CASE WHEN $3 = 'signed' THEN now() ELSE signed_at END,
    declined_reason = CASE WHEN $3 = 'declined' THEN $4 ELSE declined_reason END
WHERE id = $1 AND document_id = $2
  AND status NOT IN ('signed','accepted','declined');

-- name: MarkRecipientSent :execrows
-- Send holds the parent document row lock and re-lists recipients inside the
-- same transaction. This guarded row-counting update turns any stale/deleted
-- or non-pending recipient into a hard rollback instead of silently issuing a
-- link for a row that was not transitioned.
UPDATE recipients
SET status = 'sent',
    sent_at = now()
WHERE id = $1 AND document_id = $2 AND status = 'pending';

-- name: InvalidateRecipientTokens :exec
-- Expire every magic link when a ceremony terminates
-- (completed/declined/voided/expired) or is reopened to an editable draft for
-- revision. Defense-in-depth alongside the document-status gates ensures an
-- old signer credential can neither mutate a terminal record nor read a draft.
UPDATE recipients
SET magic_token_expires_at = now()
WHERE document_id = $1;

-- name: SetCompletedArtifactTokenExpiry :exec
-- Ordinary signer routes remain status-gated after completion. Preserve only a
-- bounded read-only final-artifact window for recipients who actually signed
-- or accepted; informational/pending recipients keep the immediate expiry set
-- by InvalidateRecipientTokens.
UPDATE recipients
SET magic_token_expires_at = sqlc.arg(magic_token_expires_at)
WHERE document_id = sqlc.arg(document_id)
  AND status IN ('signed','accepted');

-- name: RotateCompletedArtifactToken :execrows
-- Completion credentials are separate from the ceremony credential. Rotate to
-- a newly minted hash only after the parent row is terminal, and only for a
-- recipient who produced legal evidence. The signing engine additionally
-- limits recipients to the document's required roles (or non-cc acceptors),
-- while this query supplies the fail-closed state/status boundary and a row
-- count so the whole completion transaction rolls back on a stale recipient.
UPDATE recipients r
SET magic_token_hash = sqlc.arg(magic_token_hash),
    magic_token_expires_at = sqlc.arg(magic_token_expires_at)
FROM documents d
WHERE r.id = sqlc.arg(id)
  AND r.document_id = sqlc.arg(document_id)
  AND d.id = r.document_id
  AND d.status = 'completed'
  AND r.status IN ('signed','accepted');

-- name: DeleteRecipient :one
-- The document-state predicate is part of the DELETE, not only a handler
-- pre-check.  This closes the send-between-check-and-delete race that could
-- otherwise cascade through document_fields into captured signatures.
WITH draft_document AS MATERIALIZED (
  SELECT d.id
  FROM documents d
  WHERE d.id = sqlc.arg(document_id)
    AND d.status = 'draft'
  FOR UPDATE
)
DELETE FROM recipients r
USING draft_document d
WHERE r.id = sqlc.arg(id)
  AND r.document_id = sqlc.arg(document_id)
  AND d.id = r.document_id
RETURNING r.id;

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
