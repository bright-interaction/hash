-- +goose Up
CREATE TABLE webhook_endpoints (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    url                 TEXT NOT NULL,
    secret_ref          TEXT NOT NULL,
    events_subscribed   TEXT[] NOT NULL,
    active              BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_webhook_endpoints_org ON webhook_endpoints(org_id) WHERE active;

CREATE TABLE webhook_deliveries (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id         UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_id            UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','delivered','failed','retrying')),
    attempts            INTEGER NOT NULL DEFAULT 0,
    last_status_code    INTEGER,
    last_error          TEXT,
    next_attempt_at     TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_deliveries_pending ON webhook_deliveries(status, next_attempt_at)
    WHERE status IN ('pending','retrying');

-- +goose Down
DROP TABLE webhook_deliveries;
DROP TABLE webhook_endpoints;
