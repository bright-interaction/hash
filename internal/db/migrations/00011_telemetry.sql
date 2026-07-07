-- +goose Up

-- Phase 8.3: privacy-first telemetry pipeline.
--
-- Signer-side instrumentation (IntersectionObserver + scroll + click +
-- session) POSTs to /sign/{token}/telemetry. This table stores the raw
-- events for 90 days; the worker rolls them up into engagement_summary
-- and then deletes the raw rows. Heatmaps (Phase 10.1) and court-ready
-- evidence (Phase 10.2) both read from these tables.
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
-- block.viewed events here so heatmaps load fast and the raw rows can be
-- pruned at 90 days without losing the aggregate view.
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
