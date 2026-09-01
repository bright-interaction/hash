-- +goose Up
-- Signer analytics are disabled in this release, but legacy pre-release rows
-- may remain. The worker deletes raw events and recipient/document-linked
-- aggregates at the same 90-day edge; index the aggregate timestamp so that
-- privacy cleanup stays bounded as the table grows.
CREATE INDEX idx_engagement_summary_retention
    ON document_engagement_summary(last_event_at);

-- Migration 00041 retained a verbatim H1 repair snapshot for a later,
-- operator-confirmed cleanup. It is a second copy of every engagement
-- aggregate and has no timestamp-based pruning path, so keeping it would make
-- the stated 90-day analytics limit false even after the live summary and raw
-- events were deleted. The repair has now been superseded and signer
-- analytics are disabled; remove the snapshot rather than silently retaining
-- the same participant-linked data indefinitely.
DROP TABLE document_engagement_summary_h1_backup;

-- +goose Down
-- Deleting the legacy analytics snapshot is intentionally irreversible. A
-- down migration must not recreate personal data (or an unpruned side table)
-- merely to recover migration 00041's historical rollback mechanism. Runtime
-- rollback uses the compatible prior application image against the expanded
-- schema; database restoration, if ever required, uses the verified coupled
-- PostgreSQL/object-store release backup.
-- +goose StatementBegin
DO $$
BEGIN
    RAISE EXCEPTION 'cannot roll back telemetry snapshot deletion; restore the verified release backup instead';
END $$;
-- +goose StatementEnd
