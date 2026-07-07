-- +goose Up
-- Four compliance-hardening additions in one migration.
--
-- 1. Audit hash chain. Each events row now carries the SHA-256 of the
--    canonical (kind|payload|created_at|prev_hash) bytes of the
--    immediately-previous row in the org's chain. Tampering with any
--    historical row breaks every chain downstream of it, so the audit
--    log is now self-verifying without re-signing every entry.
--
-- 2. Cross-border AI transfer log. ai_completion_audit gains a
--    transfer_jurisdiction tag ("EU->EU" / "EU->US" / "EU->OTHER")
--    populated from the provider host at call time, so the Schrems II
--    transparency claim is queryable instead of inferred.
--
-- 3. Per-document lawful basis (GDPR Art. 6). Senders now select a
--    basis at send time (mostly 6(1)(b) performance-of-contract for
--    e-sign flows) and the value flows into the evidence bundle so
--    an auditor sees WHY the processing was lawful, not just THAT it
--    happened.
--
-- 4. Soft-delete on documents. DELETE used to hard-drop the row
--    including its signed-PDF cross-references; we now flip
--    deleted_at and prune after 90 days, giving GDPR DSR + erasure
--    requests a grace window without losing legal-retention records.

ALTER TABLE events
    ADD COLUMN prev_hash BYTEA,
    ADD COLUMN row_hash  BYTEA;

CREATE INDEX idx_events_chain_lookup
    ON events(org_id, created_at DESC)
    INCLUDE (id, row_hash, prev_hash);

ALTER TABLE ai_completion_audit
    ADD COLUMN transfer_jurisdiction TEXT NOT NULL DEFAULT 'unknown';

CREATE INDEX idx_ai_completion_audit_transfer
    ON ai_completion_audit(org_id, transfer_jurisdiction, created_at DESC);

ALTER TABLE documents
    ADD COLUMN lawful_basis TEXT NOT NULL DEFAULT 'contract'
        CHECK (lawful_basis IN ('contract','legal_obligation','vital_interests','public_task','legitimate_interests','consent')),
    ADD COLUMN deleted_at   TIMESTAMPTZ;

CREATE INDEX idx_documents_lawful_basis ON documents(org_id, lawful_basis)
    WHERE deleted_at IS NULL;
CREATE INDEX idx_documents_deleted_at ON documents(deleted_at)
    WHERE deleted_at IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_documents_deleted_at;
DROP INDEX IF EXISTS idx_documents_lawful_basis;
ALTER TABLE documents DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE documents DROP COLUMN IF EXISTS lawful_basis;
DROP INDEX IF EXISTS idx_ai_completion_audit_transfer;
ALTER TABLE ai_completion_audit DROP COLUMN IF EXISTS transfer_jurisdiction;
DROP INDEX IF EXISTS idx_events_chain_lookup;
ALTER TABLE events DROP COLUMN IF EXISTS row_hash;
ALTER TABLE events DROP COLUMN IF EXISTS prev_hash;
