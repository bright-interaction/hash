-- +goose Up

-- Audit 2026-07-28 H1 fix: make the engagement rollup exactly-once.
--
-- What was broken: the hourly tick fed an UNWINDOWED SUM over every surviving
-- block.viewed row (AggregateBlockViews) into an ADDITIVE ON CONFLICT upsert,
-- and re-selected any document with traffic in the last 25h every tick. The
-- entire running total was therefore re-added once an hour: a true 40 views
-- read as 180 after 8 ticks, growing without bound until total_views (INT)
-- hit "integer out of range" and that document's rollup died for good.
--
-- The shape that is correct here: claim raw rows and accumulate the claimed
-- delta. Each block.viewed row is consumed exactly once (rolled_up_at goes
-- from NULL to a timestamp inside the same statement that adds it to the
-- summary), so the additive upsert is fed a delta that can never overlap with
-- a previous tick. Replaying a tick over an already-claimed event set adds
-- nothing.
--
-- Why not "keep the full-history aggregate and make the upsert REPLACE": the
-- worker prunes raw rows at the 90-day GDPR retention edge in the same tick,
-- so a recompute-from-survivors summary silently DECAYS - a bounded counter
-- that goes down between two API polls, with the pruned events gone forever.
-- Claim-and-accumulate is the only one of the three options that survives the
-- prune, which is why document_engagement_summary can keep being the bounded
-- record after the raw events expire.

ALTER TABLE telemetry_events ADD COLUMN rolled_up_at TIMESTAMPTZ;

-- The rollup work queue. Partial index so the queue scan stays proportional
-- to unclaimed rows, not to the whole 90-day table.
CREATE INDEX idx_tel_pending_rollup ON telemetry_events (document_id)
    WHERE rolled_up_at IS NULL AND kind = 'block.viewed';

-- ---------------------------------------------------------------------------
-- Backfill. Every existing document_engagement_summary row was written by the
-- broken additive path and is inflated by an unknown per-document multiple
-- (roughly the number of hourly ticks that document was active for), so the
-- forward fix alone would leave the whole dormant corpus reading wrong at
-- GET /api/v1/documents/{id}/engagement, the get_document_engagement MCP tool
-- and OrgInsightsTopEngagedBlocks (which ORDER BYs total_dwell_ms across the
-- org, so surviving inflated rows would permanently pin the top N).
--
-- The pre-fix table is copied verbatim to document_engagement_summary_h1_backup
-- first. Nothing is destroyed without a copy, and the Down migration restores
-- the live table from it byte for byte.
-- ---------------------------------------------------------------------------

-- Columns are spelled out rather than CREATE TABLE AS so the types stay
-- explicit, and the FK keeps the GDPR posture of migration 00011: deleting a
-- document must not leave engagement rows behind in a side table. Safe to drop
-- in a later migration once the backfill has been verified in production.
CREATE TABLE document_engagement_summary_h1_backup (
    document_id     UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    block_id        TEXT NOT NULL,
    total_views     INT NOT NULL,
    total_dwell_ms  BIGINT NOT NULL,
    avg_dwell_ms    INT NOT NULL,
    last_event_at   TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    backed_up_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (document_id, block_id)
);

INSERT INTO document_engagement_summary_h1_backup (
    document_id, block_id, total_views, total_dwell_ms, avg_dwell_ms, last_event_at, updated_at
)
SELECT document_id, block_id, total_views, total_dwell_ms, avg_dwell_ms, last_event_at, updated_at
FROM document_engagement_summary;

-- Rows we cannot recompute, i.e. whose raw block.viewed events were already
-- pruned at the 90-day edge. telemetry_events shipped 2026-05-10, so on the
-- production database at the time of writing NOT ONE block.viewed row has
-- reached the retention edge yet and this count is 0, which makes this
-- backfill exact and lossless there. On any database where it is not 0, those
-- rows carry a known-inflated number that cannot be reconstructed from any
-- surviving source, so they are dropped from the live table rather than left
-- to poison the top-N ranking. The verbatim copy above is their record.
-- +goose StatementBegin
DO $$
DECLARE unrecoverable BIGINT;
BEGIN
    SELECT count(*) INTO unrecoverable
    FROM document_engagement_summary s
    WHERE NOT EXISTS (
        SELECT 1 FROM telemetry_events e
        WHERE e.document_id = s.document_id
          AND e.block_id = s.block_id
          AND e.kind = 'block.viewed'
    );
    IF unrecoverable > 0 THEN
        RAISE NOTICE 'H1 backfill: % engagement row(s) had no surviving raw block.viewed events and were dropped from document_engagement_summary; the pre-fix values are kept verbatim in document_engagement_summary_h1_backup', unrecoverable;
    END IF;
END
$$;
-- +goose StatementEnd

DELETE FROM document_engagement_summary;

-- The dwell guard: payload_json is recipient-supplied and the ingest handler
-- (internal/handler/telemetry.go) validates only kind and payload size, never
-- the type or range of dwell_ms. A bare (payload_json->>'dwell_ms')::bigint
-- therefore aborts the whole statement on {"dwell_ms":"abc"} and overflows on
-- {"dwell_ms":9223372036854775807}. Non-numbers and out-of-range values
-- contribute 0 instead of poisoning the aggregate. The nesting is deliberate:
-- Postgres does not guarantee AND short-circuits, CASE does guarantee that the
-- outer WHEN is evaluated first. 86400000 ms = 24h, above which a per-block
-- dwell is nonsense; capping there also keeps avg_dwell_ms inside INT.
INSERT INTO document_engagement_summary (
    document_id, block_id, total_views, total_dwell_ms, avg_dwell_ms, last_event_at, updated_at
)
SELECT
    document_id,
    block_id,
    COUNT(*)::int,
    COALESCE(SUM(
        CASE WHEN jsonb_typeof(payload_json->'dwell_ms') = 'number'
             THEN CASE WHEN (payload_json->>'dwell_ms')::numeric BETWEEN 0 AND 86400000
                       THEN (payload_json->>'dwell_ms')::numeric::bigint
                       ELSE 0 END
             ELSE 0 END
    ), 0)::bigint,
    (COALESCE(SUM(
        CASE WHEN jsonb_typeof(payload_json->'dwell_ms') = 'number'
             THEN CASE WHEN (payload_json->>'dwell_ms')::numeric BETWEEN 0 AND 86400000
                       THEN (payload_json->>'dwell_ms')::numeric::bigint
                       ELSE 0 END
             ELSE 0 END
    ), 0) / GREATEST(COUNT(*), 1))::int,
    MAX(created_at),
    now()
FROM telemetry_events
WHERE kind = 'block.viewed'
  AND block_id IS NOT NULL
GROUP BY document_id, block_id;

-- Everything the backfill just counted is claimed, so the first tick of the
-- new worker adds nothing on top of it.
UPDATE telemetry_events SET rolled_up_at = now() WHERE kind = 'block.viewed';

-- +goose Down
--
-- Restores the exact pre-fix snapshot. Note what that means if the fixed
-- worker has already been running: engagement accumulated since the backfill
-- is discarded along with the inflation, because the pre-fix snapshot is the
-- only thing this table can be rolled back TO. Verified by running goose down
-- then up against a real postgres:16-alpine.

DELETE FROM document_engagement_summary;

INSERT INTO document_engagement_summary (
    document_id, block_id, total_views, total_dwell_ms, avg_dwell_ms, last_event_at, updated_at
)
SELECT document_id, block_id, total_views, total_dwell_ms, avg_dwell_ms, last_event_at, updated_at
FROM document_engagement_summary_h1_backup;

DROP TABLE document_engagement_summary_h1_backup;
DROP INDEX idx_tel_pending_rollup;
ALTER TABLE telemetry_events DROP COLUMN rolled_up_at;
