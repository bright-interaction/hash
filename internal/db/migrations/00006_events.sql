-- +goose Up
-- Canonical event log for all document and signing activity. Drives the
-- timeline UI, the audit certificate, and the webhook outbound queue.

CREATE TABLE events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    document_id         UUID REFERENCES documents(id) ON DELETE CASCADE,
    recipient_id        UUID REFERENCES recipients(id) ON DELETE SET NULL,
    actor_user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    kind                TEXT NOT NULL,
    ip                  INET,
    ua                  TEXT,
    payload_json        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_events_document ON events(document_id, created_at DESC);
CREATE INDEX idx_events_org ON events(org_id, created_at DESC);
CREATE INDEX idx_events_kind ON events(kind);

-- +goose Down
DROP TABLE events;
