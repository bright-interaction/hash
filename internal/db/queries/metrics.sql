-- name: CountDocumentsByStatus :many
SELECT status, COUNT(*) AS n
FROM documents
WHERE org_id = $1
GROUP BY status;

-- name: CountSentSince :one
SELECT COUNT(*)::bigint FROM documents
WHERE org_id = $1
  AND sent_at >= $2;

-- name: CountCompletedSince :one
SELECT COUNT(*)::bigint FROM documents
WHERE org_id = $1
  AND completed_at >= $2;

-- name: CountAwaitingSig :one
SELECT COUNT(*)::bigint FROM documents
WHERE org_id = $1
  AND status IN ('sent','in_progress');

-- name: CountExpiringSoon :one
SELECT COUNT(*)::bigint FROM documents
WHERE org_id = $1
  AND status IN ('sent','in_progress')
  AND expires_at IS NOT NULL
  AND expires_at <= now() + interval '7 days';

-- name: TimeToSignP50Seconds :one
-- Median seconds between sent_at and completed_at over the last 90 days.
SELECT COALESCE(EXTRACT(EPOCH FROM percentile_cont(0.5) WITHIN GROUP (ORDER BY (completed_at - sent_at))), 0)::bigint
FROM documents
WHERE org_id = $1
  AND status = 'completed'
  AND sent_at IS NOT NULL
  AND completed_at IS NOT NULL
  AND completed_at >= now() - interval '90 days';

-- name: AgentVsHumanDocumentSplit :one
-- Documents where the create_document event was MCP-driven vs REST-driven,
-- counted from the audit log over the last 30 days.
SELECT
  COUNT(*) FILTER (WHERE payload_json->>'via' = 'mcp')::bigint AS agent,
  COUNT(*) FILTER (WHERE payload_json->>'via' IS NULL OR payload_json->>'via' = 'rest')::bigint AS human
FROM events
WHERE org_id = $1
  AND kind = 'document.created'
  AND created_at >= now() - interval '30 days';
