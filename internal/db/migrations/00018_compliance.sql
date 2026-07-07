-- +goose Up

-- Phase 12 (#8): Compliance-as-a-Service. Two tables:
--
--   compliance_baselines tracks the per-org baseline seed: which
--   business type was selected at onboarding, when, and which
--   sub-artifacts (DPA / records-of-processing / privacy notice /
--   eIDAS rules / branding) actually landed. Idempotent re-seeds
--   update the row instead of inserting another.
--
--   compliance_flags is the EDPB-update flag queue: when a feed
--   update affects a customer document, the worker writes a row
--   here. The /compliance dashboard reads from it.

CREATE TABLE compliance_baselines (
    org_id            UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    business_type     TEXT NOT NULL,                        -- 'law_firm' | 'saas' | 'consulting' | 'healthcare' | 'fintech' | 'other'
    jurisdiction      TEXT NOT NULL DEFAULT 'SE',           -- ISO country code; informs eIDAS defaults
    dpa_template_id   UUID REFERENCES templates(id) ON DELETE SET NULL,
    records_doc_id    UUID REFERENCES documents(id) ON DELETE SET NULL,
    privacy_notice_id UUID REFERENCES documents(id) ON DELETE SET NULL,
    seeded_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    schema_version    INT NOT NULL DEFAULT 1,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE compliance_flags (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    document_id       UUID REFERENCES documents(id) ON DELETE CASCADE,
    template_id       UUID REFERENCES templates(id) ON DELETE CASCADE,
    update_ref        TEXT NOT NULL,                        -- EDPB / EUR-Lex reference, e.g. 'edpb/2026/guideline-15'
    update_title      TEXT NOT NULL,
    affected_topic    TEXT NOT NULL,                        -- 'data_retention' | 'transfer_to_third_country' | etc
    block_id          TEXT NOT NULL DEFAULT '',             -- empty if doc-wide
    severity          TEXT NOT NULL DEFAULT 'review'        -- 'review' | 'urgent'
                      CHECK (severity IN ('review','urgent')),
    suggested_action  TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'open'
                      CHECK (status IN ('open','acknowledged','resolved','dismissed')),
    raised_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at       TIMESTAMPTZ
);

CREATE INDEX idx_compliance_flags_org_status
    ON compliance_flags(org_id, status, raised_at DESC);
CREATE INDEX idx_compliance_flags_doc
    ON compliance_flags(document_id, status)
    WHERE document_id IS NOT NULL;

-- EDPB feed cache so the worker doesn't refetch the same items
CREATE TABLE compliance_feed_items (
    id          TEXT PRIMARY KEY,                           -- EDPB ref, e.g. 'edpb/2026/guideline-15'
    title       TEXT NOT NULL,
    summary     TEXT NOT NULL,
    topic       TEXT NOT NULL,
    published_at TIMESTAMPTZ NOT NULL,
    seen_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_feed_published ON compliance_feed_items(published_at DESC);

-- +goose Down

DROP INDEX idx_feed_published;
DROP TABLE compliance_feed_items;
DROP INDEX idx_compliance_flags_doc;
DROP INDEX idx_compliance_flags_org_status;
DROP TABLE compliance_flags;
DROP TABLE compliance_baselines;
