-- +goose Up

-- v1.1 cleanup: track when an org was last warned at 80% of quota so the
-- worker tick is idempotent within a billing period. Reset triggers when
-- the previous warning predates the current period start.

ALTER TABLE org_subscriptions
    ADD COLUMN last_quota_warning_sent_at TIMESTAMPTZ;

-- +goose Down

ALTER TABLE org_subscriptions
    DROP COLUMN last_quota_warning_sent_at;
