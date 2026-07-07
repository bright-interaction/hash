-- name: OrgInsightsCounts :one
SELECT
    COUNT(*) FILTER (WHERE status = 'draft')::int        AS draft_count,
    COUNT(*) FILTER (WHERE status = 'sent')::int         AS sent_count,
    COUNT(*) FILTER (WHERE status = 'in_progress')::int  AS in_progress_count,
    COUNT(*) FILTER (WHERE status = 'completed')::int    AS completed_count,
    COUNT(*) FILTER (WHERE status = 'declined')::int     AS declined_count,
    COUNT(*) FILTER (WHERE status = 'voided')::int       AS voided_count,
    COUNT(*) FILTER (WHERE status = 'expired')::int      AS expired_count,
    COUNT(*)::int                                        AS total_count
FROM documents
WHERE org_id = $1 AND is_envelope = FALSE;

-- name: OrgInsightsCompletionRecent :one
SELECT
    COUNT(*)::int AS completed_30d
FROM documents
WHERE org_id = $1
  AND status = 'completed'
  AND updated_at >= now() - interval '30 days';

-- name: OrgInsightsTimeToSign :one
SELECT
    COALESCE(
        EXTRACT(EPOCH FROM percentile_cont(0.5) WITHIN GROUP (
            ORDER BY (updated_at - sent_at)
        ))::bigint,
        0
    )::bigint AS p50_seconds
FROM documents
WHERE org_id = $1
  AND status = 'completed'
  AND sent_at IS NOT NULL
  AND updated_at >= now() - interval '90 days';

-- name: OrgInsightsAgentAuthored :one
SELECT
    COUNT(*) FILTER (WHERE payload_json->>'via' = 'mcp')::int AS agent_count,
    COUNT(*) FILTER (WHERE payload_json->>'via' != 'mcp' OR payload_json->>'via' IS NULL)::int AS human_count
FROM events
WHERE org_id = $1
  AND kind IN ('document.created', 'document.updated')
  AND created_at >= now() - interval '30 days';

-- name: OrgInsightsTopEngagedBlocks :many
SELECT
    document_id,
    block_id,
    total_views,
    total_dwell_ms,
    avg_dwell_ms
FROM document_engagement_summary
WHERE document_id IN (SELECT id FROM documents WHERE org_id = $1)
ORDER BY total_dwell_ms DESC
LIMIT $2;
