-- +goose Up

-- Phase 8.3: privacy-first telemetry pipeline.
--
-- Signer-side instrumentation (IntersectionObserver + scroll + click +
-- session) POSTs to /sign/{token}/telemetry. This table stores the raw
-- events for 90 days; the worker folds each block.viewed row into
-- document_engagement_summary exactly once and deletes raw rows and expired
-- summary rows at the 90-day retention edge, NOT per rollup. Heatmaps read
-- only the surviving 90-day analytics window; telemetry is not legal evidence.
--
-- Corrected 2026-07-28 (audit H1): this header used to claim the worker
-- "deletes the raw rows" right after each rollup. That delete was never
-- implemented, and the rollup's additive upsert was written as if it had
-- been, which is what made engagement totals inflate every hour. Migration
-- 00041 makes the claim-once behaviour real instead of aspirational.
--
-- GDPR posture:
--   - ip_geo is a 2-letter country code, never a full IP or city.
--   - ua_class is 'desktop' | 'mobile' | 'tablet', never a full user agent.
--   - No cookies, no fingerprinting, no third-party domains.
--   - 90-day TTL is enforced by the worker's prune tick.

CREATE TABLE telemetry_events (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id   UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    recipient_id  UUID NOT NULL REFERENCES recipients(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN (
                    'session.start','session.end',
                    'block.viewed','page.scroll','interaction.click'
                  )),
    block_id      TEXT,
    payload_json  JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_geo        TEXT NOT NULL DEFAULT '',        -- 2-char country, or '' if unknown
    ua_class      TEXT NOT NULL DEFAULT 'unknown', -- 'desktop' | 'mobile' | 'tablet' | 'unknown'
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tel_doc      ON telemetry_events(document_id, created_at DESC);
CREATE INDEX idx_tel_recip    ON telemetry_events(recipient_id);
CREATE INDEX idx_tel_prune    ON telemetry_events(created_at);

-- Per-document, per-block dwell aggregates. The worker rolls up
-- block.viewed events here so heatmaps load fast. Aggregates are themselves
-- deleted when their newest contributing event reaches 90 days. Until then,
-- depends entirely on the rollup ACCUMULATING claimed rows rather than
-- recomputing from surviving ones: see migration 00041. A recompute-and-
-- replace rollup would partially decay a still-live summary before its single
-- explicit retention edge.
CREATE TABLE document_engagement_summary (
    document_id     UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    block_id        TEXT NOT NULL,
    total_views     INT NOT NULL DEFAULT 0,
    total_dwell_ms  BIGINT NOT NULL DEFAULT 0,
    avg_dwell_ms    INT NOT NULL DEFAULT 0,
    last_event_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (document_id, block_id)
);

CREATE INDEX idx_engagement_doc ON document_engagement_summary(document_id);

-- +goose Down

DROP TABLE document_engagement_summary;
DROP TABLE telemetry_events;
