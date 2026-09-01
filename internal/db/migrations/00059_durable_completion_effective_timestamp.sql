-- +goose Up
-- A certificate must not invent its completion time while rendering. Persist
-- one effective timestamp before the first render, carry it through the
-- durable finalization intent, and publish that exact instant as completed_at.
-- In-flight finalizations created by older code already contain a signed time
-- that PostgreSQL cannot recover, so the release must drain them explicitly.
-- Hold the inventory stable through the DDL. Without this lock, an older
-- instance could create an unbound finalization after the preflight SELECT but
-- before the new constraints are installed.
LOCK TABLE documents, document_finalization_intents IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM documents WHERE status = 'finalizing'
    ) OR EXISTS (
        SELECT 1 FROM document_finalization_intents
    ) THEN
        RAISE EXCEPTION 'completion timestamp cutover requires every in-flight finalization to be drained';
    END IF;
    IF EXISTS (
        SELECT 1 FROM documents
        WHERE status = 'completed' AND completed_at IS NULL
    ) THEN
        RAISE EXCEPTION 'completion timestamp cutover found a completed document without completed_at';
    END IF;
    IF EXISTS (
        SELECT 1 FROM documents
        WHERE status <> 'completed' AND completed_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'completion timestamp cutover found a non-completed document with completed_at';
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE documents
    ADD COLUMN completion_effective_at TIMESTAMPTZ,
    -- FALSE identifies only completed evidence produced before this migration:
    -- its database completed_at is known, but that instant was not committed
    -- by the historical certificate/audit payload and must not be relabeled.
    ADD COLUMN completion_effective_at_bound BOOLEAN NOT NULL DEFAULT FALSE;

-- Existing terminal records retain their historical database completion
-- instant. New ceremonies set this column before any certificate is rendered.
UPDATE documents
SET completion_effective_at = completed_at
WHERE status = 'completed';

-- Every non-terminal row can safely use the new ceremony before it produces
-- evidence. New rows also default to bound; only historical completed rows
-- remain explicitly legacy-unbound.
UPDATE documents
SET completion_effective_at_bound = TRUE
WHERE status <> 'completed';

ALTER TABLE documents
    ALTER COLUMN completion_effective_at_bound SET DEFAULT TRUE;

ALTER TABLE document_finalization_intents
    ADD COLUMN completion_effective_at TIMESTAMPTZ NOT NULL;

ALTER TABLE documents
    ADD CONSTRAINT documents_completion_timestamps_consistent CHECK (
        (status = 'finalizing' AND completion_effective_at_bound AND completion_effective_at IS NOT NULL AND completed_at IS NULL)
        OR
        (status = 'completed' AND completion_effective_at IS NOT NULL AND completed_at = completion_effective_at)
        OR
        (status NOT IN ('finalizing', 'completed') AND completion_effective_at_bound AND completion_effective_at IS NULL AND completed_at IS NULL)
    );

-- +goose StatementBegin
CREATE FUNCTION reject_completion_commitment_rewrite()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- FALSE is a migration-time provenance label for rows that were already
    -- completed before this cutover. Never let a later INSERT manufacture a
    -- record that verifiers would mistake for that legacy inventory.
    IF TG_OP = 'INSERT' THEN
        IF NOT NEW.completion_effective_at_bound THEN
            RAISE EXCEPTION 'new documents must bind completion-effective timestamp provenance';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.completion_effective_at IS NOT NULL
       AND NEW.completion_effective_at IS DISTINCT FROM OLD.completion_effective_at THEN
        RAISE EXCEPTION 'documents.completion_effective_at is immutable once set';
    END IF;
    IF NEW.completion_effective_at_bound IS DISTINCT FROM OLD.completion_effective_at_bound THEN
        RAISE EXCEPTION 'documents.completion_effective_at_bound is immutable';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER documents_completion_commitment_immutable
BEFORE UPDATE OF completion_effective_at, completion_effective_at_bound ON documents
FOR EACH ROW
EXECUTE FUNCTION reject_completion_commitment_rewrite();

CREATE TRIGGER documents_completion_commitment_new_rows_bound
BEFORE INSERT ON documents
FOR EACH ROW
EXECUTE FUNCTION reject_completion_commitment_rewrite();

-- +goose Down
-- Keep the one-way provenance decision and the destructive column drop in one
-- write-excluding critical section. Otherwise a bound completion could commit
-- after the guard SELECT and lose its classification during rollback.
LOCK TABLE documents, document_finalization_intents IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM documents WHERE status = 'finalizing'
    ) OR EXISTS (
        SELECT 1 FROM document_finalization_intents
    ) THEN
        RAISE EXCEPTION 'cannot roll back completion timestamps while finalizations are in flight';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM documents
        WHERE status = 'completed'
          AND completion_effective_at_bound
    ) THEN
        RAISE EXCEPTION 'cannot roll back completion timestamps after bound evidence has been completed';
    END IF;
END $$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS documents_completion_commitment_new_rows_bound ON documents;
DROP TRIGGER IF EXISTS documents_completion_commitment_immutable ON documents;
DROP FUNCTION IF EXISTS reject_completion_commitment_rewrite();
ALTER TABLE documents
    DROP CONSTRAINT IF EXISTS documents_completion_timestamps_consistent;
ALTER TABLE document_finalization_intents
    DROP COLUMN IF EXISTS completion_effective_at;
ALTER TABLE documents
    DROP COLUMN IF EXISTS completion_effective_at_bound,
    DROP COLUMN IF EXISTS completion_effective_at;
