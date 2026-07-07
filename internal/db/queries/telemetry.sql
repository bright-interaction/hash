-- name: InsertTelemetryEvent :one
INSERT INTO telemetry_events (
    document_id, recipient_id, kind, block_id, payload_json, ip_geo, ua_class
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
) RETURNING *;

-- name: ListTelemetryByDocument :many
SELECT * FROM telemetry_events
WHERE document_id = $1
ORDER BY created_at DESC
LIMIT $2;

-- name: PruneTelemetryOlderThan :execrows
DELETE FROM telemetry_events
WHERE created_at < $1;

-- Aggregation queries for the rollup tick. We pull rows in document
-- batches, compute summaries, and upsert into document_engagement_summary.

-- name: ListDocumentsWithRecentTelemetry :many
SELECT DISTINCT document_id
FROM telemetry_events
WHERE created_at > $1
ORDER BY document_id;

-- name: AggregateBlockViews :many
SELECT
    block_id,
    COUNT(*)::int                                      AS view_count,
    COALESCE(SUM((payload_json->>'dwell_ms')::bigint), 0)::bigint AS total_dwell_ms,
    MAX(created_at)                                    AS last_event_at
FROM telemetry_events
WHERE document_id = $1
  AND kind = 'block.viewed'
  AND block_id IS NOT NULL
GROUP BY block_id;

-- name: UpsertEngagementSummary :exec
INSERT INTO document_engagement_summary (
    document_id, block_id, total_views, total_dwell_ms, avg_dwell_ms, last_event_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6, now()
)
ON CONFLICT (document_id, block_id) DO UPDATE SET
    total_views    = document_engagement_summary.total_views    + EXCLUDED.total_views,
    total_dwell_ms = document_engagement_summary.total_dwell_ms + EXCLUDED.total_dwell_ms,
    avg_dwell_ms   = CASE
                       WHEN document_engagement_summary.total_views + EXCLUDED.total_views > 0
                       THEN ((document_engagement_summary.total_dwell_ms + EXCLUDED.total_dwell_ms)
                             / (document_engagement_summary.total_views + EXCLUDED.total_views))::int
                       ELSE 0
                     END,
    last_event_at  = GREATEST(document_engagement_summary.last_event_at, EXCLUDED.last_event_at),
    updated_at     = now();

-- name: ListEngagementByDocument :many
SELECT * FROM document_engagement_summary
WHERE document_id = $1
ORDER BY total_dwell_ms DESC;

