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

-- Prune raw rows past the 90-day GDPR TTL (migration 00011). Returns how many
-- rows went, and how many of them were block.viewed rows that reached the
-- retention edge WITHOUT ever being claimed by the rollup. That second number
-- must be 0 in steady state: the tick rolls up before it prunes, so a non-zero
-- value means engagement events were destroyed uncounted (worker down for 90
-- days, or RollupBlockViews erroring for one document every tick). It is
-- reported so that loss is loud instead of silent. The prune itself is NOT
-- made conditional on the rollup succeeding, because the 90-day TTL is a
-- privacy commitment and must not be held hostage to an aggregation bug.
-- name: PruneTelemetryOlderThan :one
WITH pruned AS (
    DELETE FROM telemetry_events
    WHERE created_at < $1
    RETURNING kind, rolled_up_at
)
SELECT
    COUNT(*)                                                                     AS deleted_rows,
    COUNT(*) FILTER (WHERE kind = 'block.viewed' AND rolled_up_at IS NULL)       AS unrolled_views
FROM pruned;

-- Rollup queries. See migration 00041 for why this is claim-and-accumulate
-- rather than recompute-and-replace. The short version: the worker deletes raw
-- rows at the 90-day retention edge, so any summary recomputed from surviving
-- raw rows would decay downward and lose history that only the summary still
-- holds. Here every block.viewed row is consumed exactly once, so the additive
-- ON CONFLICT is fed a delta that can never overlap a previous tick.

-- name: ListDocumentsWithPendingRollup :many
SELECT DISTINCT document_id
FROM telemetry_events
WHERE rolled_up_at IS NULL
  AND kind = 'block.viewed'
  AND block_id IS NOT NULL
ORDER BY document_id;

-- Claim this document's unrolled block.viewed rows and fold them into the
-- summary in ONE statement. The UPDATE ... RETURNING CTE takes a row lock on
-- each claimed row and flips rolled_up_at, so a second worker running the same
-- statement concurrently re-evaluates `rolled_up_at IS NULL` after the lock is
-- released and claims nothing. If the INSERT half fails the claim rolls back
-- with it, so a failed tick loses no events. Replaying the statement over an
-- already-claimed event set inserts nothing and adds nothing.
--
-- The nested CASE around dwell_ms is a guard, not decoration: payload_json is
-- recipient-supplied and internal/handler/telemetry.go validates only kind and
-- payload size. A bare ::bigint cast aborts on {"dwell_ms":"abc"} and
-- overflows on {"dwell_ms":9223372036854775807}, which froze the document's
-- summary forever (the audit's terminal failure mode, reachable in two POSTs).
-- Postgres does not guarantee AND short-circuits; CASE does guarantee the
-- outer WHEN runs first. 86400000 ms = 24h caps a nonsense dwell and keeps
-- avg_dwell_ms inside INT.
-- name: RollupBlockViews :execrows
WITH consumed AS (
    UPDATE telemetry_events
       SET rolled_up_at = now()
     WHERE document_id = $1
       AND kind = 'block.viewed'
       AND block_id IS NOT NULL
       AND rolled_up_at IS NULL
    RETURNING block_id, payload_json, created_at
), delta AS (
    SELECT
        block_id,
        COUNT(*)::int AS view_count,
        COALESCE(SUM(
            CASE WHEN jsonb_typeof(payload_json->'dwell_ms') = 'number'
                 THEN CASE WHEN (payload_json->>'dwell_ms')::numeric BETWEEN 0 AND 86400000
                           THEN (payload_json->>'dwell_ms')::numeric::bigint
                           ELSE 0 END
                 ELSE 0 END
        ), 0)::bigint AS dwell_ms,
        MAX(created_at) AS last_event_at
    FROM consumed
    GROUP BY block_id
)
INSERT INTO document_engagement_summary AS s (
    document_id, block_id, total_views, total_dwell_ms, avg_dwell_ms, last_event_at, updated_at
)
SELECT
    $1,
    d.block_id,
    d.view_count,
    d.dwell_ms,
    (d.dwell_ms / GREATEST(d.view_count, 1))::int,
    d.last_event_at,
    now()
FROM delta d
ON CONFLICT (document_id, block_id) DO UPDATE SET
    total_views    = s.total_views    + EXCLUDED.total_views,
    total_dwell_ms = s.total_dwell_ms + EXCLUDED.total_dwell_ms,
    avg_dwell_ms   = ((s.total_dwell_ms + EXCLUDED.total_dwell_ms)
                      / GREATEST(s.total_views + EXCLUDED.total_views, 1))::int,
    last_event_at  = GREATEST(s.last_event_at, EXCLUDED.last_event_at),
    updated_at     = now();

-- name: ListEngagementByDocument :many
SELECT * FROM document_engagement_summary
WHERE document_id = $1
ORDER BY total_dwell_ms DESC;

