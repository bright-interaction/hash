-- name: CreateDataSubjectRequest :one
INSERT INTO data_subject_requests (
    org_id, document_id, recipient_id, subject_email, subject_name,
    kind, requested_via, requested_note, payload_json
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: ListDataSubjectRequestsByOrg :many
SELECT * FROM data_subject_requests
WHERE org_id = $1
  AND ($2::text = '' OR status = $2)
ORDER BY requested_at DESC
LIMIT $3;

-- name: GetDataSubjectRequest :one
SELECT * FROM data_subject_requests
WHERE id = $1 AND org_id = $2;

-- name: GetDataSubjectRequestForUpdate :one
-- Serialize competing fulfill/deny/withdraw transitions. All destructive
-- erasure work and its audit rows run in the same caller-owned transaction
-- while this lock is held.
SELECT * FROM data_subject_requests
WHERE id = $1 AND org_id = $2
FOR UPDATE;

-- name: UpdateDataSubjectRequestStatus :one
UPDATE data_subject_requests
SET status          = sqlc.arg(status),
    resolution_note = sqlc.arg(resolution_note),
    fulfilled_by    = sqlc.arg(fulfilled_by),
    fulfilled_at    = CASE WHEN sqlc.arg(status)::text IN ('fulfilled','denied','withdrawn') THEN now() ELSE NULL END
WHERE id = sqlc.arg(id)
  AND org_id = sqlc.arg(org_id)
  AND status = sqlc.arg(expected_status)
RETURNING *;

-- name: AnonymizeRecipient :execrows
-- Erasure under GDPR Art. 17 with the Art. 17(3)(e) retention override
-- baked in: signed-PDF retention is a legal requirement so we cannot
-- delete the document. We redact the PII fields on the recipient row
-- while keeping the audit trail (signature timestamps, IP country) so
-- the cert remains verifiable. Idempotent: re-running is a no-op.
--
-- Org-scoped through the documents FK: recipients carry no org_id, so a
-- raw `WHERE id = $1` is globally addressable and was the sink for a
-- cross-tenant erasure IDOR. The JOIN + org predicate means a recipient
-- belonging to another tenant matches 0 rows; callers treat 0 rows as a
-- hard failure so a stale/cross-tenant id can never report "fulfilled".
UPDATE recipients r
SET email = $2,
    name = $3
FROM documents d
WHERE r.id = $1
  AND r.document_id = d.id
  AND d.org_id = $4;

-- name: ExportSubjectData :many
-- Article 15 + 20 data export: every recipient row for the supplied
-- email across the org, with the parent document context. Sender
-- workflow joins this to the signed PDFs in MinIO when fulfilling.
SELECT r.id            AS recipient_id,
       r.email         AS recipient_email,
       r.name          AS recipient_name,
       r.role          AS recipient_role,
       r.status        AS recipient_status,
       r.created_at    AS recipient_created_at,
       r.signed_at     AS recipient_signed_at,
       r.first_viewed_at AS recipient_first_viewed_at,
       d.id            AS document_id,
       d.name          AS document_name,
       d.status        AS document_status,
       d.created_at    AS document_created_at,
       d.final_pdf_key AS document_final_pdf_key,
       d.audit_cert_key AS document_audit_cert_key
FROM recipients r
JOIN documents d ON d.id = r.document_id
WHERE d.org_id = $1
  AND lower(r.email) = lower($2)
ORDER BY d.created_at DESC;

-- name: AnonymizeSignaturesByRecipient :execrows
-- Erasure completeness (Art 17): the signatures row independently stores the
-- signer's typed legal name, IP and user-agent. These are NOT the retained
-- evidentiary artefact (the signed PDF + cert verify from signed_at +
-- image_sha256), so they are redacted alongside the recipient row rather than
-- kept under the 17(3)(e) override. Org-scoped via the documents FK so a
-- cross-tenant recipient_id matches 0 rows. Idempotent.
UPDATE signatures s
SET typed_name = $2,
    signer_ip = NULL,
    signer_ua = NULL
FROM documents d
WHERE s.recipient_id = $1
  AND s.document_id = d.id
  AND d.org_id = $3;

-- name: RedactDSRSubjectIdentifiers :execrows
-- L7: the erasure request row itself stores subject_email + subject_name; once
-- fulfilled they are no longer needed (the request id ties the row to the audit
-- trail) and must not linger in plaintext. Redact in place, org-scoped.
UPDATE data_subject_requests
SET subject_email = $3,
    subject_name = $4
WHERE id = $1 AND org_id = $2;
