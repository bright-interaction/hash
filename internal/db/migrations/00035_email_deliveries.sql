-- +goose Up
-- Durable outbound email queue. Until now invites/reminders/completion emails
-- were sent fire-and-forget straight to SMTP, so a transient SMTP outage
-- silently dropped them and broke the core send loop. The QueueingMailer now
-- persists every message here; the worker's email-dispatch loop sends it with
-- backoff retries, mirroring the webhook_deliveries durability model.
CREATE TABLE email_deliveries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    to_email        TEXT NOT NULL,
    subject         TEXT NOT NULL,
    html_body       TEXT NOT NULL,
    text_body       TEXT NOT NULL,
    reply_to        TEXT NOT NULL DEFAULT '',
    from_name       TEXT NOT NULL DEFAULT '',
    headers_json    JSONB NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'retrying', 'sent', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT NOT NULL DEFAULT '',
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at         TIMESTAMPTZ
);

CREATE INDEX idx_email_deliveries_due ON email_deliveries (next_attempt_at)
    WHERE status IN ('pending', 'retrying');

-- +goose Down
DROP TABLE email_deliveries;
