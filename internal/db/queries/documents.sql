-- name: CreateBlocksDocument :one
INSERT INTO documents (org_id, template_id, name, source_kind, blocks_json, variables_json, sender_id, expires_at)
VALUES ($1, $2, $3, 'blocks', $4, $5, $6, $7)
RETURNING *;

-- name: CreatePDFDocument :one
INSERT INTO documents (
    org_id, template_id, name, source_kind,
    pdf_storage_key, pdf_sha256, pdf_storage_version_id,
    evidence_version_pins_required, sender_id, expires_at
)
VALUES ($1, $2, $3, 'pdf', $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetDocument :one
SELECT * FROM documents WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL;

-- name: GetDocumentForUpdate :one
-- Row-locking read used by the signing engine to serialize concurrent
-- sign/decline/finalize on the same document inside a transaction.
SELECT * FROM documents WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL FOR UPDATE;

-- name: GetDocumentForShare :one
-- Long-running signer clarification holds a SHARE row lock so revise/resend and
-- every other document mutation wait for one ceremony epoch, while the
-- separately committed request audit and AI-completion audit can still take
-- their foreign-key KEY SHARE locks without self-deadlocking.
SELECT * FROM documents WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL FOR SHARE;

-- name: GetDocumentByID :one
-- System-level lookup by id alone (no org scope) for the background worker,
-- which holds a document_id (from a reminder row) but not the org. Callers
-- must be system contexts, never request-scoped handlers.
SELECT * FROM documents WHERE id = $1;

-- name: ListDocuments :many
SELECT * FROM documents
WHERE org_id = $1
  AND deleted_at IS NULL
  AND ($2::TEXT[] IS NULL OR status = ANY($2::TEXT[]))
ORDER BY updated_at DESC
LIMIT $3 OFFSET $4;

-- name: CountDocuments :one
SELECT COUNT(*) FROM documents
WHERE org_id = $1
  AND deleted_at IS NULL
  AND ($2::TEXT[] IS NULL OR status = ANY($2::TEXT[]));

-- name: UpdateDocumentBlocks :one
UPDATE documents
SET blocks_json = $3,
    variables_json = $4,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'draft' AND source_kind = 'blocks'
RETURNING *;

-- name: UpdateDocumentMetadata :one
UPDATE documents
SET name = $3,
    expires_at = $4,
    metadata = $5,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'draft'
RETURNING *;

-- name: SetDocumentDefaultLocale :one
-- The sender's document-level default signing language. Draft-only: once sent,
-- recipients are locked, so the default can no longer change.
UPDATE documents
SET default_locale = $3,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'draft'
RETURNING *;

-- name: SetDocumentStatus :one
-- The generic state helper must never allocate a durable send/finalization
-- lifecycle state. Those transitions own immutable Article 13, retention, and
-- completion commitments and must use their dedicated guarded queries.
UPDATE documents
SET status = $3,
    updated_at = now()
WHERE id = $1 AND org_id = $2
  AND (
    ($3 = 'in_progress' AND documents.status = 'sent')
    OR ($3 = 'expired' AND documents.status IN ('sent', 'in_progress'))
  )
RETURNING *;

-- name: SetDocumentRequiresSignature :one
-- Draft-only toggle between signature-required and acknowledgement (view/accept)
-- mode. Locked once sent so recipients can't have the rules change under them.
UPDATE documents
SET requires_signature = $3,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'draft'
RETURNING *;

-- name: DeclineDocumentIfActive :one
-- Guarded decline transition: only an active (sent/in_progress) document can
-- move to declined. A completed/voided/declined/expired doc returns no row,
-- so a recipient with a still-live magic link cannot flip a terminal contract
-- to declined.
UPDATE documents
SET status = 'declined',
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status IN ('sent','in_progress')
RETURNING *;

-- name: VoidDocumentIfActive :one
-- Guarded void transition: only an active sent/in-progress ceremony can be
-- voided. Draft, paused, and every terminal state return no row. This closes the Void race
-- where a plain GetDocument + unguarded status write could overwrite a doc
-- that finalize had just flipped to 'completed' (finalize holds only the
-- advisory lock, not a row lock) back to 'voided'. Mirrors
-- DeclineDocumentIfActive.
UPDATE documents
SET status = 'voided',
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status IN ('sent', 'in_progress')
RETURNING *;

-- name: RequestChangesOnDocument :one
-- Guarded: an active (sent/in_progress) document pauses for changes. Already
-- paused (changes_requested) is allowed too so a signer can mark several spans.
UPDATE documents
SET status = 'changes_requested',
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status IN ('sent','in_progress','changes_requested')
RETURNING *;

-- name: ExpireDocumentIfActive :one
-- Atomic expiration transition. The worker first discovers candidates with
-- GetExpirableDocuments, then uses this guarded write inside a transaction with
-- token invalidation + reminder cancellation. If signing/finalization wins the
-- race and makes the document terminal, this returns no row and the worker must
-- perform no expiration side effects.
UPDATE documents
SET status = 'expired',
    updated_at = now()
WHERE id = $1
  AND org_id = $2
  AND expires_at IS NOT NULL
  AND expires_at <= clock_timestamp()
  AND status IN ('sent','in_progress')
RETURNING *;

-- name: ApplyBlocksForChange :one
-- Apply an auto-approved inline change to a paused document's blocks. Scoped to
-- changes_requested so it only runs during the negotiation window.
UPDATE documents
SET blocks_json = $3,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'changes_requested'
RETURNING *;

-- name: ReopenDocumentToDraft :one
-- The sender revises after a change request: a paused document returns to draft
-- so it can be edited and re-sent. article13_notice_epoch_at deliberately
-- survives: the next sealing completion must allocate a strictly newer epoch.
UPDATE documents
SET status = 'draft',
    sent_at = NULL,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'changes_requested'
RETURNING *;

-- name: GetStrandedDocuments :many
-- Documents ready for terminal artifact completion but stranded in_progress,
-- plus finalizing documents whose exact staged artifacts need retention or a
-- terminal SQL retry after a crash.
-- SQL deliberately selects a broad bounded candidate set. Required roles for
-- block documents depend on the frozen conditional tree and custom roles, so
-- reimplementing that expression language in JSONPath would diverge from the
-- signer/PDF projection. The signing engine is the sole readiness authority
-- and re-checks the exact frozen role set before any terminal write.
-- Keep crash-resume work ahead of not-yet-claimed rows, but select the oldest
-- candidate in each class first. Newer failures must not continually displace
-- a contract that has already waited longer; id makes equal timestamps stable.
SELECT d.* FROM documents d
WHERE d.status IN ('in_progress','finalizing')
  AND d.final_pdf_key IS NULL
  AND d.deleted_at IS NULL
  -- Envelope children share their root's ceremony, terminal artifact, and
  -- finalization intent. They must never be retried as standalone documents.
  AND d.parent_envelope_id IS NULL
  AND (
    d.status = 'finalizing'
    OR
    (
      d.requires_signature = false
      AND NOT EXISTS (
        SELECT 1 FROM recipients r
        WHERE r.document_id = d.id
          AND r.role <> 'cc'
          AND r.status NOT IN ('accepted','declined')
      )
    )
    OR (
      d.requires_signature = true
      AND EXISTS (
        SELECT 1 FROM recipients signed
        WHERE signed.document_id = d.id
          AND signed.status = 'signed'
      )
    )
  )
ORDER BY (d.status = 'finalizing') DESC, d.updated_at ASC, d.id ASC
LIMIT $1;

-- name: DeleteDraftDocument :exec
-- Soft-delete: flip deleted_at so the row stays available for GDPR
-- Art. 15 / Art. 30 evidence retrieval during the 90-day grace
-- window. A separate worker prunes anything past that boundary.
UPDATE documents
SET deleted_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'draft' AND deleted_at IS NULL;

-- name: SetDocumentLawfulBasis :exec
UPDATE documents
SET lawful_basis = $3
WHERE id = $1 AND org_id = $2;

-- name: ClaimSoftDeletedDocumentsForPurge :many
-- Lease a bounded batch before object-store cleanup. updated_at doubles as a
-- recoverable lease timestamp for already-deleted drafts: peers skip a claim
-- for 15 minutes, while a crashed worker leaves it eligible for a later retry.
-- The row remains intact until its document-owned source object is confirmed
-- deleted, preserving the key needed to retry storage cleanup.
WITH candidates AS (
  SELECT documents.id
  FROM documents
  WHERE documents.deleted_at IS NOT NULL
    AND documents.deleted_at < sqlc.arg(cutoff)
    AND documents.status = 'draft'
    AND documents.updated_at <= now() - interval '15 minutes'
  ORDER BY documents.deleted_at
  FOR UPDATE SKIP LOCKED
  LIMIT sqlc.arg(batch_limit)
)
UPDATE documents d
SET updated_at = now()
FROM candidates
WHERE d.id = candidates.id
RETURNING d.*;

-- name: DeleteClaimedSoftDeletedDocument :execrows
-- Hard-delete only the exact draft lease the worker just cleaned. If any
-- concurrent state change touched updated_at, the CAS fails and no legal row is
-- removed. events.document_id uses ON DELETE SET NULL, preserving the org chain.
DELETE FROM documents
WHERE id = $1
  AND org_id = $2
  AND deleted_at IS NOT NULL
  AND deleted_at < $3
  AND status = 'draft'
  AND updated_at = $4;

-- name: SearchDocumentsByName :many
SELECT * FROM documents
WHERE org_id = $1 AND deleted_at IS NULL AND name ILIKE '%' || $2 || '%'
ORDER BY updated_at DESC
LIMIT $3;

-- name: GetExpirableDocuments :many
SELECT * FROM documents
WHERE expires_at IS NOT NULL
  AND deleted_at IS NULL
  AND expires_at <= now()
  AND status IN ('sent','in_progress')
LIMIT $1;
