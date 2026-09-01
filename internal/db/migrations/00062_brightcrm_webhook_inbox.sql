-- +goose Up

-- Resolve inbound BrightCRM changes without scanning every variable binding.
-- document_id is included so the join to documents can use the same index-only
-- path after the exact source tuple has been selected.
CREATE INDEX idx_var_bindings_source_lookup
    ON document_variable_bindings (source_kind, source_ref, document_id);

-- BrightCRM supplies a stable delivery id on retryable outbound webhooks. Hash
-- stores only keyed correlation tokens, never the raw provider id or payload,
-- and claims the receipt in the same transaction as every affected tenant's
-- audit append. This makes a retry either append all ledgers once or none.
CREATE TABLE brightcrm_webhook_receipts (
    delivery_correlation TEXT PRIMARY KEY
        CHECK (delivery_correlation ~ '^[0-9a-f]{64}$'),
    payload_correlation TEXT NOT NULL
        CHECK (payload_correlation ~ '^[0-9a-f]{64}$'),
    -- Preserve the exact, sorted tenant set whose immutable ledgers were
    -- appended with this claim. A later retry must never re-resolve bindings:
    -- doing so could invalidate a newly bound tenant without an audit record.
    org_ids UUID[] NOT NULL,
    CHECK (array_position(org_ids, NULL) IS NULL),
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Match the audit-ledger horizon so even very late provider retries cannot
    -- amplify immutable webhook.received rows while that ledger is retained.
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '7 years'),
    CHECK (expires_at > received_at)
);

CREATE INDEX idx_brightcrm_webhook_receipts_expiry
    ON brightcrm_webhook_receipts (expires_at, delivery_correlation);

-- +goose Down

-- +goose StatementBegin
DO $$
BEGIN
    LOCK TABLE brightcrm_webhook_receipts IN ACCESS EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM brightcrm_webhook_receipts LIMIT 1) THEN
        RAISE EXCEPTION
            'cannot roll back migration 00062 after durable BrightCRM webhook receipts exist; preserve replay protection';
    END IF;
END
$$;
-- +goose StatementEnd

DROP TABLE brightcrm_webhook_receipts;
DROP INDEX idx_var_bindings_source_lookup;
