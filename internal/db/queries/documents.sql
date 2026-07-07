-- name: CreateBlocksDocument :one
INSERT INTO documents (org_id, template_id, name, source_kind, blocks_json, variables_json, sender_id, expires_at)
VALUES ($1, $2, $3, 'blocks', $4, $5, $6, $7)
RETURNING *;

-- name: CreatePDFDocument :one
INSERT INTO documents (org_id, template_id, name, source_kind, pdf_storage_key, pdf_sha256, sender_id, expires_at)
VALUES ($1, $2, $3, 'pdf', $4, $5, $6, $7)
RETURNING *;

-- name: GetDocument :one
SELECT * FROM documents WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL;

-- name: GetDocumentForUpdate :one
-- Row-locking read used by the signing engine to serialize concurrent
-- sign/decline/finalize on the same document inside a transaction.
SELECT * FROM documents WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL FOR UPDATE;

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
UPDATE documents
SET status = $3,
    sent_at = CASE WHEN $3 = 'sent' THEN now() ELSE sent_at END,
    completed_at = CASE WHEN $3 = 'completed' THEN now() ELSE completed_at END,
    updated_at = now()
WHERE id = $1 AND org_id = $2
RETURNING *;

-- name: SetDocumentFinal :execrows
-- Terminal write, guarded to status = 'in_progress'. finalize renders the PDF +
-- audit cert (slow Gotenberg calls) while holding only the per-document
-- advisory lock, NOT a row lock, so a concurrent Revise (-> draft, signatures
-- deleted) or Void (-> voided) can move the row out from under it. Requiring
-- status = 'in_progress' here (rather than merely <> 'completed') means such a
-- revised/voided document can NOT be flipped to 'completed' with a rendered PDF
-- + audit cert that embed now-invalid signatures. The caller inspects the
-- affected-row count: 0 rows means the document left in_progress mid-finalize,
-- so completion is aborted. A second finalize (retry worker racing the last
-- signer) short-circuits on the FinalPdfKey idempotency check before this write.
UPDATE documents
SET final_pdf_key = $3,
    final_pdf_sha = $4,
    audit_cert_key = $5,
    completed_at = now(),
    status = 'completed',
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'in_progress';

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
-- Guarded void transition: only a non-terminal document can be voided. A
-- completed or already-voided doc returns no row. This closes the Void race
-- where a plain GetDocument + unguarded status write could overwrite a doc
-- that finalize had just flipped to 'completed' (finalize holds only the
-- advisory lock, not a row lock) back to 'voided'. Mirrors
-- DeclineDocumentIfActive.
UPDATE documents
SET status = 'voided',
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status NOT IN ('completed', 'voided')
RETURNING *;

-- name: RequestChangesOnDocument :one
-- Guarded: an active (sent/in_progress) document pauses for changes. Already
-- paused (changes_requested) is allowed too so a signer can mark several spans.
UPDATE documents
SET status = 'changes_requested',
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status IN ('sent','in_progress','changes_requested')
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
-- so it can be edited and re-sent.
UPDATE documents
SET status = 'draft',
    sent_at = NULL,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'changes_requested'
RETURNING *;

-- name: GetStrandedDocuments :many
-- Documents where every signer has signed but finalize never completed (no
-- final PDF, status still in_progress). These are Gotenberg/MinIO failure
-- casualties; the finalize-retry worker re-invokes finalize idempotently.
SELECT d.* FROM documents d
WHERE d.status = 'in_progress'
  AND d.final_pdf_key IS NULL
  AND d.deleted_at IS NULL
  AND NOT EXISTS (
    SELECT 1 FROM recipients r
    WHERE r.document_id = d.id
      AND r.role = 'signer'
      AND r.status NOT IN ('signed','declined')
  )
  AND EXISTS (
    SELECT 1 FROM recipients r2
    WHERE r2.document_id = d.id AND r2.role = 'signer' AND r2.status = 'signed'
  )
ORDER BY d.updated_at ASC
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

-- name: PurgeSoftDeletedDocuments :exec
-- Restricted to draft-only: DeleteDraftDocument (the only soft-delete entry
-- point) is draft-scoped, so this never hard-drops a signed/completed legal
-- record. Combined with events.document_id ON DELETE SET NULL (migration
-- 00029), a purge can no longer snap the org audit hash chain.
DELETE FROM documents
WHERE deleted_at IS NOT NULL AND deleted_at < $1 AND status = 'draft';

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
