-- +goose Up
-- v1.2 second wave: per-endpoint webhook secrets so customers rotate keys
-- independently and a stolen secret only compromises one integration.
--
-- The old `secret_ref` column kept a customer-facing label (env-var name);
-- actual signing used a single HASH_WEBHOOK_SECRET from the worker config.
-- New `secret` column carries the per-endpoint signing key generated at
-- create time; the REST + MCP create handlers reveal it ONCE (mirror of the
-- per-document agent-token pattern from v1.1) so customers can paste it
-- into their downstream signature verifier. `secret_ref` stays for
-- backward-compat reads but is no longer signed against.
ALTER TABLE webhook_endpoints
    ADD COLUMN secret TEXT NOT NULL DEFAULT '';

-- Existing rows: leave secret = '' so the dispatcher falls back to the
-- legacy HASH_WEBHOOK_SECRET. New rows must always carry a fresh secret.
-- The handler + MCP enforce non-empty at insert time.

-- +goose Down
ALTER TABLE webhook_endpoints DROP COLUMN secret;
