-- +goose Up

-- Phase 9.2 (#4): smart eIDAS tier escalation. Rules describe predicates
-- over document metadata + resolved variables; if any rule matches, the
-- send is gated unless the recipient flow at-or-above the required tier.
--
-- predicate_json shape:
--   { "field": "variables.deal_amount" | "amount" | "country" | "document_type",
--     "op":    ">=" | ">" | "<=" | "<" | "==" | "in",
--     "value": 100000 | "SE" | ["SE","NO"] }
--
-- required_tier is one of 'SES' | 'AES' | 'QES' (low to high). On send,
-- Hash evaluates every rule, takes the highest required tier across
-- matches, and refuses the send if the recipient flow tier (currently
-- 'SES' by default; 'AES' / 'QES' wired in 11+ via Idura/Signicat) is
-- below.
--
-- priority: lower number = evaluated first (informational; the chosen
-- tier is still the max across all matched rules).

CREATE TABLE eidas_routing_rules (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    priority      INT  NOT NULL DEFAULT 100,
    predicate_json JSONB NOT NULL,
    required_tier TEXT NOT NULL CHECK (required_tier IN ('SES','AES','QES')),
    reason        TEXT NOT NULL DEFAULT '',
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_eidas_org_active ON eidas_routing_rules(org_id, active, priority);

-- documents grow a per-doc routing tier so a sender can pre-commit to a
-- tier before the rules engine fires (e.g. "this contract goes QES even
-- if the rules would allow AES").
ALTER TABLE documents
    ADD COLUMN routing_tier TEXT NOT NULL DEFAULT 'SES'
        CHECK (routing_tier IN ('SES','AES','QES'));

-- +goose Down

ALTER TABLE documents DROP COLUMN routing_tier;
DROP INDEX idx_eidas_org_active;
DROP TABLE eidas_routing_rules;
