-- +goose Up
CREATE TABLE reminders (
    document_id     UUID PRIMARY KEY REFERENCES documents(id) ON DELETE CASCADE,
    schedule_json   JSONB NOT NULL DEFAULT '[{"days_after_send":3},{"days_after_send":7}]'::jsonb,
    next_fire_at    TIMESTAMPTZ NOT NULL,
    last_fired_at   TIMESTAMPTZ,
    fires_remaining INTEGER NOT NULL DEFAULT 2
);

CREATE INDEX idx_reminders_next ON reminders(next_fire_at)
    WHERE fires_remaining > 0;

-- +goose Down
DROP TABLE reminders;
