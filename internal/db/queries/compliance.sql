-- name: UpsertComplianceBaseline :one
INSERT INTO compliance_baselines (
    org_id, business_type, jurisdiction,
    dpa_template_id, records_doc_id, privacy_notice_id
) VALUES (
    $1, $2, $3, $4, $5, $6
)
ON CONFLICT (org_id) DO UPDATE SET
    business_type    = EXCLUDED.business_type,
    jurisdiction     = EXCLUDED.jurisdiction,
    dpa_template_id  = COALESCE(EXCLUDED.dpa_template_id,  compliance_baselines.dpa_template_id),
    records_doc_id   = COALESCE(EXCLUDED.records_doc_id,   compliance_baselines.records_doc_id),
    privacy_notice_id = COALESCE(EXCLUDED.privacy_notice_id, compliance_baselines.privacy_notice_id),
    updated_at       = now()
RETURNING *;

-- name: GetComplianceBaseline :one
SELECT * FROM compliance_baselines WHERE org_id = $1;

-- name: InsertComplianceFlag :one
INSERT INTO compliance_flags (
    org_id, document_id, template_id, update_ref, update_title,
    affected_topic, block_id, severity, suggested_action
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
)
ON CONFLICT DO NOTHING
RETURNING *;

-- name: ListComplianceFlags :many
SELECT * FROM compliance_flags
WHERE org_id = $1
  AND ($2::text = '' OR status = $2)
ORDER BY raised_at DESC
LIMIT $3;

-- name: SetComplianceFlagStatus :one
UPDATE compliance_flags
   SET status      = $3,
       resolved_at = CASE WHEN $3 IN ('resolved','dismissed') THEN now() ELSE resolved_at END
 WHERE id = $1 AND org_id = $2
RETURNING *;

-- name: UpsertFeedItem :exec
INSERT INTO compliance_feed_items (id, title, summary, topic, published_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (id) DO UPDATE SET
    title        = EXCLUDED.title,
    summary      = EXCLUDED.summary,
    topic        = EXCLUDED.topic,
    published_at = EXCLUDED.published_at;

-- name: ListAllOrgsForCompliance :many
SELECT id FROM orgs ORDER BY id ASC;
