-- name: BeginDocumentSendSealing :one
UPDATE documents
SET status = 'sealing', updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'draft' AND deleted_at IS NULL
RETURNING *;

-- name: BeginEnvelopeChildrenSendSealing :many
UPDATE documents
SET status = 'sealing', updated_at = now()
WHERE parent_envelope_id = $1
  AND org_id = $2
  AND status = 'draft'
  AND deleted_at IS NULL
RETURNING *;

-- name: CreateSendSealingIntent :one
-- Pin the next ceremony epoch and its exact seven-year Object Lock deadline in
-- the same durable row before any S3 mutation. The database clock may move
-- backwards; the parent/child high-water marks still force strict monotonicity.
WITH next_epoch AS MATERIALIZED (
    SELECT GREATEST(
        statement_timestamp(),
        clock_timestamp(),
        COALESCE(parent.article13_notice_epoch_at + interval '1 microsecond', '-infinity'::timestamptz),
        COALESCE((
            SELECT max(child.article13_notice_epoch_at) + interval '1 microsecond'
            FROM documents child
            WHERE child.parent_envelope_id = parent.id
              AND child.org_id = parent.org_id
        ), '-infinity'::timestamptz)
    ) AS value
    FROM documents parent
    WHERE parent.id = sqlc.arg(document_id)
      AND parent.org_id = sqlc.arg(org_id)
      AND parent.status = 'draft'
      AND parent.deleted_at IS NULL
)
INSERT INTO send_sealing_intents (
    document_id, org_id, actor_user_id, actor_email, actor_ip, via, tool,
    article13_notice_epoch_at, retain_until
)
SELECT
    sqlc.arg(document_id), sqlc.arg(org_id), sqlc.narg(actor_user_id),
    sqlc.arg(actor_email), sqlc.arg(actor_ip), sqlc.arg(via), sqlc.arg(tool),
    next_epoch.value, hash_evidence_retain_until(next_epoch.value, 7)
FROM next_epoch
RETURNING *;

-- name: GetSendSealingIntent :one
SELECT * FROM send_sealing_intents
WHERE document_id = $1 AND org_id = $2;

-- name: GetSendSealingIntentForUpdate :one
SELECT * FROM send_sealing_intents
WHERE document_id = $1 AND org_id = $2
FOR UPDATE;

-- name: IsSendSealingExpired :one
-- Use the database clock while the caller holds the document row lock. This
-- decides whether irreversible recovery may expose invites or must atomically
-- land in expired without emitting a born-expired signing link.
SELECT expires_at IS NOT NULL AND expires_at <= clock_timestamp()
FROM documents
WHERE id = $1 AND org_id = $2 AND status = 'sealing';

-- name: ListPendingSendSealingIntents :many
SELECT * FROM send_sealing_intents
ORDER BY updated_at, document_id
LIMIT $1;

-- name: PinDocumentSendEvidenceVersions :one
-- A pre-VersionId document may already be active or enter sealing with
-- digest-only source/rendered commitments. Resolve those versions once, then
-- persist the pins while the document is non-editable. Send invokes this before
-- retention_started_at; finalization invokes it before any source read. A retry
-- may supply the same values but can never replace an existing pin.
UPDATE documents
SET pdf_storage_version_id = CASE
        WHEN pdf_storage_key IS NULL THEN NULL
        ELSE COALESCE(pdf_storage_version_id, sqlc.narg(pdf_storage_version_id)::text)
    END,
    rendered_pdf_version_id = CASE
        WHEN rendered_pdf_key IS NULL THEN NULL
        ELSE COALESCE(rendered_pdf_version_id, sqlc.narg(rendered_pdf_version_id)::text)
    END,
    evidence_version_pins_required = TRUE,
    updated_at = now()
WHERE id = sqlc.arg(id)
  AND org_id = sqlc.arg(org_id)
  AND status IN ('sealing','sent','in_progress','finalizing')
  AND deleted_at IS NULL
  AND (
    (pdf_storage_key IS NULL AND sqlc.narg(pdf_storage_version_id)::text IS NULL)
    OR (
      pdf_storage_key IS NOT NULL
      AND NULLIF(sqlc.narg(pdf_storage_version_id)::text, '') IS NOT NULL
      AND (pdf_storage_version_id IS NULL OR pdf_storage_version_id = sqlc.narg(pdf_storage_version_id)::text)
    )
  )
  AND (
    (rendered_pdf_key IS NULL AND sqlc.narg(rendered_pdf_version_id)::text IS NULL)
    OR (
      rendered_pdf_key IS NOT NULL
      AND NULLIF(sqlc.narg(rendered_pdf_version_id)::text, '') IS NOT NULL
      AND (rendered_pdf_version_id IS NULL OR rendered_pdf_version_id = sqlc.narg(rendered_pdf_version_id)::text)
    )
  )
RETURNING *;

-- name: MarkSendSealingRetentionComplete :execrows
UPDATE send_sealing_intents
SET retention_completed_at = COALESCE(retention_completed_at, now()),
    attempts = attempts + 1,
    last_error = NULL,
    updated_at = now()
WHERE document_id = $1 AND org_id = $2
  AND retention_started_at IS NOT NULL
  AND retain_until = hash_evidence_retain_until(article13_notice_epoch_at, 7);

-- name: MarkSendSealingRetentionStarted :execrows
UPDATE send_sealing_intents
SET retention_started_at = COALESCE(retention_started_at, now()),
    updated_at = now()
WHERE document_id = $1 AND org_id = $2
  AND retention_completed_at IS NULL
  AND retain_until = hash_evidence_retain_until(article13_notice_epoch_at, 7);

-- name: MarkSendSealingAttemptFailed :execrows
UPDATE send_sealing_intents
SET attempts = attempts + 1,
    last_error = $3,
    updated_at = now()
WHERE document_id = $1 AND org_id = $2;

-- name: CompleteDocumentSendSealing :one
-- Consume the epoch pinned before retention. Completion never samples a clock.
WITH ceremony_epoch AS MATERIALIZED (
    SELECT intent.article13_notice_epoch_at AS value
    FROM send_sealing_intents intent
    WHERE intent.document_id = $1
      AND intent.org_id = $2
      AND intent.retention_started_at IS NOT NULL
      AND intent.retention_completed_at IS NOT NULL
      AND intent.retain_until = hash_evidence_retain_until(intent.article13_notice_epoch_at, 7)
)
UPDATE documents
SET status = 'sent',
    sent_at = ceremony_epoch.value,
    article13_notice_epoch_at = ceremony_epoch.value,
    article13_notice_schema = 'hash-a13-2026-08-31',
    article13_notice_epoch_v61_committed = TRUE,
    updated_at = now()
FROM ceremony_epoch
WHERE documents.id = $1 AND documents.org_id = $2
  AND documents.status = 'sealing'
  AND documents.deleted_at IS NULL
  AND documents.evidence_version_pins_required = TRUE
  AND (
      documents.article13_notice_epoch_at IS NULL
      OR ceremony_epoch.value > documents.article13_notice_epoch_at
  )
RETURNING documents.*;

-- name: CompleteEnvelopeChildrenSendSealing :many
UPDATE documents
SET status = 'sent',
    sent_at = parent.sent_at,
    article13_notice_epoch_at = parent.article13_notice_epoch_at,
    article13_notice_schema = parent.article13_notice_schema,
    article13_notice_epoch_v61_committed = TRUE,
    updated_at = now()
FROM documents parent
WHERE documents.parent_envelope_id = $1
  AND documents.org_id = $2
  AND documents.status = 'sealing'
  AND documents.deleted_at IS NULL
  AND documents.evidence_version_pins_required = TRUE
  AND parent.id = $1
  AND parent.org_id = $2
  AND parent.status = 'sent'
  AND parent.sent_at IS NOT NULL
  AND parent.article13_notice_epoch_at = parent.sent_at
  AND parent.article13_notice_schema <> ''
  AND parent.article13_notice_epoch_v61_committed
  AND (
      documents.article13_notice_epoch_at IS NULL
      OR parent.article13_notice_epoch_at > documents.article13_notice_epoch_at
  )
  AND EXISTS (
      SELECT 1
      FROM send_sealing_intents i
      WHERE i.document_id = documents.parent_envelope_id
        AND i.org_id = documents.org_id
        AND i.article13_notice_epoch_at = parent.article13_notice_epoch_at
        AND i.retention_started_at IS NOT NULL
        AND i.retention_completed_at IS NOT NULL
        AND i.retain_until = hash_evidence_retain_until(i.article13_notice_epoch_at, 7)
  )
RETURNING documents.*;

-- name: AbortDocumentSendSealing :execrows
UPDATE documents
SET status = 'draft', updated_at = now()
WHERE id = $1 AND org_id = $2 AND status = 'sealing' AND deleted_at IS NULL;

-- name: AbortEnvelopeChildrenSendSealing :execrows
UPDATE documents
SET status = 'draft', updated_at = now()
WHERE parent_envelope_id = $1 AND org_id = $2 AND status = 'sealing' AND deleted_at IS NULL;

-- name: DeleteSendSealingIntent :execrows
DELETE FROM send_sealing_intents
WHERE document_id = $1 AND org_id = $2;
