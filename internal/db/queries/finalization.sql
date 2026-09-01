-- name: BeginDocumentFinalization :one
-- The surrounding transaction holds the root row lock and has rechecked the
-- exact recipient readiness predicate. Capture one post-readiness timestamp,
-- but never let database clock rollback place completion before the durable
-- send epoch or any already-committed response/signature in the envelope
-- family. PostgreSQL timestamps have microsecond precision, so advancing each
-- prior high-water by one microsecond gives a strict and representable order.
WITH finalizing_root AS MATERIALIZED (
    SELECT d.id, d.org_id, d.sent_at
    FROM documents d
    WHERE d.id = sqlc.arg(id)
      AND d.org_id = sqlc.arg(org_id)
      AND d.status = 'in_progress'
      AND d.sent_at IS NOT NULL
      AND d.deleted_at IS NULL
), lifecycle_clock AS MATERIALIZED (
    SELECT root.id,
           GREATEST(
               statement_timestamp(),
               COALESCE((
                   SELECT max(member.sent_at) + interval '1 microsecond'
                   FROM documents member
                   WHERE member.id = root.id OR member.parent_envelope_id = root.id
               ), '-infinity'::timestamptz),
               COALESCE((
                   SELECT max(r.signed_at) + interval '1 microsecond'
                   FROM recipients r
                   JOIN documents member ON member.id = r.document_id
                   WHERE member.id = root.id OR member.parent_envelope_id = root.id
               ), '-infinity'::timestamptz),
               COALESCE((
                   SELECT max(s.signed_at) + interval '1 microsecond'
                   FROM signatures s
                   JOIN documents member ON member.id = s.document_id
                   WHERE member.id = root.id OR member.parent_envelope_id = root.id
               ), '-infinity'::timestamptz),
               COALESCE((
                   SELECT max(e.created_at) + interval '1 microsecond'
                   FROM events e
                   JOIN documents member ON member.id = e.document_id
                   WHERE e.org_id = root.org_id
                     AND (member.id = root.id OR member.parent_envelope_id = root.id)
               ), '-infinity'::timestamptz)
           ) AS effective_at
    FROM finalizing_root root
)
UPDATE documents AS target
SET status = 'finalizing',
    completion_effective_at_bound = TRUE,
    completion_effective_at = COALESCE(target.completion_effective_at, lifecycle_clock.effective_at),
    -- Object Lock timestamps have whole-second precision. Round upward after
    -- the calendar-year addition so the deadline is never even fractionally
    -- shorter than the configured retention period.
    finalization_retain_until = COALESCE(
        finalization_retain_until,
        hash_evidence_retain_until(
            COALESCE(target.completion_effective_at, lifecycle_clock.effective_at),
            sqlc.arg(retention_years)::integer
        )
    ),
    updated_at = lifecycle_clock.effective_at
FROM lifecycle_clock
WHERE target.id = lifecycle_clock.id
  AND target.id = sqlc.arg(id)
  AND target.org_id = sqlc.arg(org_id)
  AND target.status = 'in_progress'
  AND target.sent_at IS NOT NULL
  AND target.deleted_at IS NULL
RETURNING target.*;

-- name: CreateDocumentFinalizationIntent :one
INSERT INTO document_finalization_intents (
    document_id, org_id, mode, completion_effective_at, retain_until,
    final_pdf_key, final_pdf_sha256, final_pdf_version_id,
    audit_cert_key, audit_cert_sha256, audit_cert_version_id,
    audit_payload_key, audit_payload_sha256, audit_payload_version_id,
    audit_signature_key, audit_signature_sha256, audit_signature_version_id
) VALUES (
    sqlc.arg(document_id), sqlc.arg(org_id), sqlc.arg(mode), sqlc.arg(completion_effective_at), sqlc.arg(retain_until),
    sqlc.arg(final_pdf_key), sqlc.arg(final_pdf_sha256), sqlc.arg(final_pdf_version_id),
    sqlc.arg(audit_cert_key), sqlc.arg(audit_cert_sha256), sqlc.arg(audit_cert_version_id),
    sqlc.arg(audit_payload_key), sqlc.arg(audit_payload_sha256), sqlc.arg(audit_payload_version_id),
    sqlc.arg(audit_signature_key), sqlc.arg(audit_signature_sha256), sqlc.arg(audit_signature_version_id)
)
RETURNING *;

-- name: GetDocumentFinalizationIntent :one
SELECT * FROM document_finalization_intents
WHERE document_id = $1 AND org_id = $2;

-- name: GetDocumentFinalizationIntentForUpdate :one
SELECT * FROM document_finalization_intents
WHERE document_id = $1 AND org_id = $2
FOR UPDATE;

-- name: PinLegacyDocumentFinalizationIntentVersions :one
-- Existing finalizing rows from before migration 47 have digest commitments but
-- no VersionIds. Resolve each once, persist all four atomically, then every
-- verify/retain/publish retry becomes exact-version only.
UPDATE document_finalization_intents
SET final_pdf_version_id = sqlc.arg(final_pdf_version_id),
    audit_cert_version_id = sqlc.arg(audit_cert_version_id),
    audit_payload_version_id = sqlc.arg(audit_payload_version_id),
    audit_signature_version_id = sqlc.arg(audit_signature_version_id),
    evidence_version_pins_required = TRUE,
    updated_at = now()
WHERE document_id = sqlc.arg(document_id)
  AND org_id = sqlc.arg(org_id)
  AND evidence_version_pins_required = FALSE
  AND final_pdf_version_id IS NULL
  AND audit_cert_version_id IS NULL
  AND audit_payload_version_id IS NULL
  AND audit_signature_version_id IS NULL
RETURNING *;

-- name: ListPendingDocumentFinalizations :many
SELECT * FROM document_finalization_intents
ORDER BY updated_at, document_id
LIMIT $1;

-- name: MarkDocumentFinalizationRetentionStarted :execrows
UPDATE document_finalization_intents
SET retention_started_at = COALESCE(retention_started_at, now()), updated_at = now()
WHERE document_id = $1 AND org_id = $2
  AND retention_completed_at IS NULL
  AND retain_until IS NOT NULL;

-- name: MarkDocumentFinalizationRetentionComplete :execrows
UPDATE document_finalization_intents
SET retention_completed_at = COALESCE(retention_completed_at, now()),
    attempts = attempts + 1, last_error = NULL, updated_at = now()
WHERE document_id = $1 AND org_id = $2
  AND retention_started_at IS NOT NULL
  AND retain_until IS NOT NULL;

-- name: MarkDocumentFinalizationAttemptFailed :execrows
UPDATE document_finalization_intents
SET attempts = attempts + 1, last_error = $3, updated_at = now()
WHERE document_id = $1 AND org_id = $2;

-- name: CompleteDocumentFinalization :one
UPDATE documents
SET final_pdf_key = sqlc.arg(final_pdf_key),
    final_pdf_sha = sqlc.arg(final_pdf_sha256),
    final_pdf_version_id = sqlc.arg(final_pdf_version_id),
    audit_cert_key = sqlc.arg(audit_cert_key),
    audit_cert_sha256 = sqlc.arg(audit_cert_sha256),
    audit_cert_version_id = sqlc.arg(audit_cert_version_id),
    audit_payload_key = sqlc.arg(audit_payload_key),
    audit_payload_sha256 = sqlc.arg(audit_payload_sha256),
    audit_payload_version_id = sqlc.arg(audit_payload_version_id),
    audit_signature_key = sqlc.arg(audit_signature_key),
    audit_signature_sha256 = sqlc.arg(audit_signature_sha256),
    audit_signature_version_id = sqlc.arg(audit_signature_version_id),
    completed_at = documents.completion_effective_at,
    status = 'completed', updated_at = now()
WHERE documents.id = sqlc.arg(id)
  AND documents.org_id = sqlc.arg(org_id)
  AND documents.status = 'finalizing'
  AND documents.completion_effective_at_bound = TRUE
  AND documents.finalization_retain_until IS NOT NULL
  AND documents.evidence_version_pins_required = TRUE
  -- The terminal row can only publish the exact staged objects after their
  -- durable retention checkpoint. This SQL guard is independent of the Go
  -- orchestration so a future caller cannot bypass Object Lock completion.
  AND EXISTS (
    SELECT 1
    FROM document_finalization_intents i
    WHERE i.document_id = documents.id
      AND i.org_id = documents.org_id
      AND i.completion_effective_at = documents.completion_effective_at
      AND i.retain_until = documents.finalization_retain_until
      AND i.retention_completed_at IS NOT NULL
      AND i.final_pdf_key = sqlc.arg(final_pdf_key)
      AND i.final_pdf_sha256 = sqlc.arg(final_pdf_sha256)
      AND i.final_pdf_version_id = sqlc.arg(final_pdf_version_id)
      AND i.audit_cert_key = sqlc.arg(audit_cert_key)
      AND i.audit_cert_sha256 = sqlc.arg(audit_cert_sha256)
      AND i.audit_cert_version_id = sqlc.arg(audit_cert_version_id)
      AND i.audit_payload_key = sqlc.arg(audit_payload_key)
      AND i.audit_payload_sha256 = sqlc.arg(audit_payload_sha256)
      AND i.audit_payload_version_id = sqlc.arg(audit_payload_version_id)
      AND i.audit_signature_key = sqlc.arg(audit_signature_key)
      AND i.audit_signature_sha256 = sqlc.arg(audit_signature_sha256)
      AND i.audit_signature_version_id = sqlc.arg(audit_signature_version_id)
      AND i.evidence_version_pins_required = TRUE
  )
RETURNING *;

-- name: DeleteDocumentFinalizationIntent :execrows
DELETE FROM document_finalization_intents
WHERE document_id = $1 AND org_id = $2;
