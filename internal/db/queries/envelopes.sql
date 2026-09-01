-- name: ListEnvelopeChildren :many
SELECT * FROM documents
WHERE parent_envelope_id = $1 AND org_id = $2
ORDER BY envelope_position ASC NULLS LAST, created_at ASC;

-- name: AttachToEnvelope :one
-- Lock the draft parent before touching the child. Send takes the same row
-- lock, so membership cannot change once its transactional transition begins.
-- Keeping the eligibility checks in this statement also closes the preflight
-- race in which a child was sent, nested, or attached elsewhere after the API
-- read it.
WITH locked_parent AS MATERIALIZED (
    SELECT parent.id, parent.org_id
      FROM documents AS parent
     WHERE parent.id = $2
       AND parent.org_id = $4
       AND parent.status = 'draft'
       AND parent.is_envelope = TRUE
       AND parent.parent_envelope_id IS NULL
       AND parent.deleted_at IS NULL
     FOR UPDATE OF parent
)
UPDATE documents AS child
   SET parent_envelope_id = $2,
       envelope_position  = $3,
       updated_at         = now()
  FROM locked_parent
 WHERE child.id = $1
   AND child.org_id = locked_parent.org_id
   AND child.status = 'draft'
   AND child.is_envelope = FALSE
   AND child.parent_envelope_id IS NULL
   AND child.deleted_at IS NULL
RETURNING child.*;

-- name: DetachFromEnvelope :one
-- Resolve and lock the current parent first. This shares the send lock order
-- and makes both the parent and child draft checks part of the mutation.
WITH locked_parent AS MATERIALIZED (
    SELECT parent.id
      FROM documents AS parent
      JOIN documents AS current_child
        ON current_child.parent_envelope_id = parent.id
       AND current_child.id = $1
       AND current_child.org_id = $2
       AND current_child.status = 'draft'
       AND current_child.is_envelope = FALSE
       AND current_child.deleted_at IS NULL
     WHERE parent.org_id = $2
       AND parent.status = 'draft'
       AND parent.is_envelope = TRUE
       AND parent.parent_envelope_id IS NULL
       AND parent.deleted_at IS NULL
     FOR UPDATE OF parent
)
UPDATE documents AS child
   SET parent_envelope_id = NULL,
       envelope_position  = NULL,
       updated_at         = now()
  FROM locked_parent
 WHERE child.id = $1
   AND child.org_id = $2
   AND child.parent_envelope_id = locked_parent.id
   AND child.status = 'draft'
   AND child.is_envelope = FALSE
   AND child.deleted_at IS NULL
RETURNING child.*;

-- name: ReorderEnvelopeChild :execrows
-- org_id is REQUIRED: without it an org-A caller could reorder an org-B envelope's
-- children by supplying their UUIDs (the only envelope mutation that was missing the
-- tenant predicate; reachable cross-tenant via the MCP reorder tool).
-- The parent lock also serializes this mutation against send. :execrows is
-- intentional: callers must reject zero affected rows instead of reporting a
-- successful reorder after the envelope or child left draft state.
WITH locked_parent AS MATERIALIZED (
    SELECT parent.id
      FROM documents AS parent
     WHERE parent.id = $2
       AND parent.org_id = $4
       AND parent.status = 'draft'
       AND parent.is_envelope = TRUE
       AND parent.parent_envelope_id IS NULL
       AND parent.deleted_at IS NULL
     FOR UPDATE OF parent
)
UPDATE documents AS child
   SET envelope_position = $3,
       updated_at        = now()
  FROM locked_parent
 WHERE child.id = $1
   AND child.parent_envelope_id = locked_parent.id
   AND child.parent_envelope_id = $2
   AND child.org_id = $4
   AND child.status = 'draft'
   AND child.is_envelope = FALSE
   AND child.deleted_at IS NULL;

-- name: MarkAsEnvelope :one
UPDATE documents
   SET is_envelope = TRUE,
       updated_at  = now()
 WHERE id = $1 AND org_id = $2
   AND status = 'draft'
   AND parent_envelope_id IS NULL
   AND source_kind = 'blocks'
   AND deleted_at IS NULL
RETURNING *;

-- name: MaxEnvelopePosition :one
SELECT COALESCE(MAX(envelope_position), 0)::int AS max_pos
FROM documents
WHERE parent_envelope_id = $1;

-- name: BeginEnvelopeChildrenFinalization :many
-- The caller holds the root and every child row lock before the parent claim
-- allocates its completion timestamp. Move the entire family into the same
-- non-interactive state in that transaction and copy, rather than recompute,
-- the root's exact completion and retention commitments. A child-addressed
-- comment or other lifecycle mutation therefore either commits before the
-- family high-water snapshot or observes finalizing and fails closed.
UPDATE documents AS child
SET status = 'finalizing',
    completion_effective_at_bound = parent.completion_effective_at_bound,
    completion_effective_at = parent.completion_effective_at,
    finalization_retain_until = parent.finalization_retain_until,
    updated_at = parent.completion_effective_at
FROM documents AS parent
WHERE child.parent_envelope_id = $1
  AND child.org_id = $2
  AND child.status IN ('sent','in_progress')
  AND child.deleted_at IS NULL
  AND parent.id = $1
  AND parent.org_id = $2
  AND parent.status = 'finalizing'
  AND parent.is_envelope = TRUE
  AND parent.parent_envelope_id IS NULL
  AND parent.deleted_at IS NULL
  AND parent.completion_effective_at_bound = TRUE
  AND parent.completion_effective_at IS NOT NULL
  AND parent.finalization_retain_until IS NOT NULL
RETURNING child.*;

-- name: CompleteEnvelopeChildren :many
-- Children share the envelope's immutable final artifact. Persist every key
-- and the digest in one statement; setting status alone creates completed rows
-- whose final-PDF and evidence downloads fail.
UPDATE documents AS child
SET final_pdf_key = $3,
    final_pdf_sha = $4,
    final_pdf_version_id = $5,
    audit_cert_key = $6,
    audit_cert_sha256 = $7,
    audit_cert_version_id = $8,
    audit_payload_key = $9,
    audit_payload_sha256 = $10,
    audit_payload_version_id = $11,
    audit_signature_key = $12,
    audit_signature_sha256 = $13,
    audit_signature_version_id = $14,
    status = 'completed',
    completion_effective_at_bound = parent.completion_effective_at_bound,
    completion_effective_at = parent.completion_effective_at,
    finalization_retain_until = parent.finalization_retain_until,
    completed_at = parent.completion_effective_at,
    updated_at = now()
FROM documents AS parent
WHERE child.parent_envelope_id = $1
  AND child.org_id = $2
  AND child.status = 'finalizing'
  AND child.completion_effective_at_bound = TRUE
  AND child.evidence_version_pins_required = TRUE
  AND parent.id = $1
  AND parent.org_id = $2
  AND parent.status = 'completed'
  AND parent.completion_effective_at_bound = TRUE
  AND parent.completion_effective_at IS NOT NULL
  AND parent.finalization_retain_until IS NOT NULL
  AND child.completion_effective_at = parent.completion_effective_at
  AND child.finalization_retain_until = parent.finalization_retain_until
RETURNING child.*;
