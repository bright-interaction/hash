-- +goose Up
-- Object Lock COMPLIANCE retention can be lengthened but never shortened.
-- Persist each lifecycle operation's exact target before its first S3 mutation
-- so a crash/retry reuses the original deadline instead of computing now()+7y
-- and silently extending personal-data retention on every attempt.
--
-- Migration 00059 requires in-flight finalizations to be drained. Repeat that
-- boundary here, and refuse every pre-control send intent: none contains the
-- authoritative future sent_at from which a truthful deadline can be derived.
-- The release must be quiesced so an older instance cannot recreate either
-- inventory between the adjacent migrations.
LOCK TABLE documents IN ACCESS EXCLUSIVE MODE;
LOCK TABLE send_sealing_intents IN ACCESS EXCLUSIVE MODE;
LOCK TABLE document_finalization_intents IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM documents WHERE status = 'sealing')
       OR EXISTS (SELECT 1 FROM send_sealing_intents) THEN
        RAISE EXCEPTION 'retention deadline cutover requires every pre-control send sealing intent to be explicitly drained';
    END IF;
    IF EXISTS (SELECT 1 FROM documents WHERE status = 'finalizing')
       OR EXISTS (SELECT 1 FROM document_finalization_intents) THEN
        RAISE EXCEPTION 'retention deadline cutover requires every in-flight finalization to be drained';
    END IF;
    IF EXISTS (
        SELECT 1 FROM documents
        WHERE status = 'completed' AND completion_effective_at_bound
    ) THEN
        RAISE EXCEPTION 'retention deadline cutover found a post-00059 completion without an exact durable retention deadline';
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE send_sealing_intents
    ADD COLUMN retain_until TIMESTAMPTZ;

ALTER TABLE documents
    ADD COLUMN finalization_retain_until TIMESTAMPTZ;

ALTER TABLE document_finalization_intents
    ADD COLUMN retain_until TIMESTAMPTZ NOT NULL;

-- Go's time.AddDate normalizes a leap-day anniversary into March 1 when the
-- target year has no February 29. PostgreSQL's direct `+ interval 'N years'`
-- clamps to February 28, so spell out the same UTC calendar normalization used
-- by the application and round the final target upward to S3's whole second.
-- +goose StatementBegin
CREATE FUNCTION hash_evidence_retain_until(anchor TIMESTAMPTZ, retention_years INTEGER)
RETURNS TIMESTAMPTZ
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
WITH raw_target AS (
    SELECT
        make_date(
            extract(year FROM anchor AT TIME ZONE 'UTC')::integer + retention_years,
            extract(month FROM anchor AT TIME ZONE 'UTC')::integer,
            1
        )::timestamp
        + ((extract(day FROM anchor AT TIME ZONE 'UTC')::integer - 1) * interval '1 day')
        + ((anchor AT TIME ZONE 'UTC') - date_trunc('day', anchor AT TIME ZONE 'UTC')) AS value
)
SELECT (
    date_trunc('second', value)
    + CASE
        WHEN value = date_trunc('second', value) THEN interval '0 seconds'
        ELSE interval '1 second'
      END
) AT TIME ZONE 'UTC'
FROM raw_target;
$$;
-- +goose StatementEnd

ALTER TABLE send_sealing_intents
    ADD CONSTRAINT send_sealing_retain_until_second_precision CHECK (
        retain_until IS NULL OR retain_until = date_trunc('second', retain_until)
    ),
    ADD CONSTRAINT send_sealing_started_has_retain_until CHECK (
        retention_started_at IS NULL OR retain_until IS NOT NULL
    );

ALTER TABLE documents
    ADD CONSTRAINT documents_finalization_retain_until_valid CHECK (
        (
            status IN ('finalizing', 'completed')
            AND completion_effective_at_bound
            AND sent_at IS NOT NULL
            AND completion_effective_at IS NOT NULL
            AND completion_effective_at > sent_at
            AND finalization_retain_until IS NOT NULL
            AND finalization_retain_until = hash_evidence_retain_until(completion_effective_at, 7)
            AND finalization_retain_until = date_trunc('second', finalization_retain_until)
        )
        OR (
            status = 'completed'
            AND NOT completion_effective_at_bound
            AND finalization_retain_until IS NULL
        )
        OR (
            status NOT IN ('finalizing', 'completed')
            AND finalization_retain_until IS NULL
        )
    ),
    -- Give the intent a database-enforced identity for the exact deadline it
    -- inherits. The document id is already globally unique, but PostgreSQL
    -- needs an explicit matching key for the composite foreign key below.
    ADD CONSTRAINT documents_finalization_retain_until_identity UNIQUE (
        id, org_id, finalization_retain_until
    );

ALTER TABLE document_finalization_intents
    ADD CONSTRAINT finalization_intent_retain_until_valid CHECK (
        retain_until = hash_evidence_retain_until(completion_effective_at, 7)
        AND retain_until = date_trunc('second', retain_until)
    ),
    ADD CONSTRAINT finalization_intent_retain_until_matches_document
        FOREIGN KEY (document_id, org_id, retain_until)
        REFERENCES documents (id, org_id, finalization_retain_until)
        ON DELETE RESTRICT;

-- +goose StatementBegin
CREATE FUNCTION reject_retain_until_rewrite()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.retain_until IS NOT NULL
       AND NEW.retain_until IS DISTINCT FROM OLD.retain_until THEN
        RAISE EXCEPTION '%.retain_until is immutable once set', TG_TABLE_NAME;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER send_sealing_retain_until_immutable
BEFORE UPDATE OF retain_until ON send_sealing_intents
FOR EACH ROW
EXECUTE FUNCTION reject_retain_until_rewrite();

CREATE TRIGGER finalization_intent_retain_until_immutable
BEFORE UPDATE OF retain_until ON document_finalization_intents
FOR EACH ROW
EXECUTE FUNCTION reject_retain_until_rewrite();

-- +goose StatementBegin
CREATE FUNCTION reject_finalization_retain_until_rewrite()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.finalization_retain_until IS NOT NULL
       AND NEW.finalization_retain_until IS DISTINCT FROM OLD.finalization_retain_until THEN
        RAISE EXCEPTION 'documents.finalization_retain_until is immutable once set';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER documents_finalization_retain_until_immutable
BEFORE UPDATE OF finalization_retain_until ON documents
FOR EACH ROW
EXECUTE FUNCTION reject_finalization_retain_until_rewrite();

-- +goose Down
LOCK TABLE documents IN ACCESS EXCLUSIVE MODE;
LOCK TABLE send_sealing_intents IN ACCESS EXCLUSIVE MODE;
LOCK TABLE document_finalization_intents IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM documents WHERE status IN ('sealing', 'finalizing'))
       OR EXISTS (SELECT 1 FROM documents WHERE finalization_retain_until IS NOT NULL)
       OR EXISTS (SELECT 1 FROM send_sealing_intents)
       OR EXISTS (SELECT 1 FROM document_finalization_intents) THEN
        RAISE EXCEPTION 'cannot roll back retention deadlines while durable retention commitments or lifecycle operations exist';
    END IF;
END $$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS documents_finalization_retain_until_immutable ON documents;
DROP FUNCTION IF EXISTS reject_finalization_retain_until_rewrite();
DROP TRIGGER IF EXISTS finalization_intent_retain_until_immutable ON document_finalization_intents;
DROP TRIGGER IF EXISTS send_sealing_retain_until_immutable ON send_sealing_intents;
DROP FUNCTION IF EXISTS reject_retain_until_rewrite();

ALTER TABLE document_finalization_intents
    DROP CONSTRAINT IF EXISTS finalization_intent_retain_until_matches_document,
    DROP CONSTRAINT IF EXISTS finalization_intent_retain_until_valid,
    DROP COLUMN IF EXISTS retain_until;

ALTER TABLE documents
    DROP CONSTRAINT IF EXISTS documents_finalization_retain_until_identity,
    DROP CONSTRAINT IF EXISTS documents_finalization_retain_until_valid,
    DROP COLUMN IF EXISTS finalization_retain_until;

ALTER TABLE send_sealing_intents
    DROP CONSTRAINT IF EXISTS send_sealing_started_has_retain_until,
    DROP CONSTRAINT IF EXISTS send_sealing_retain_until_second_precision,
    DROP COLUMN IF EXISTS retain_until;

DROP FUNCTION IF EXISTS hash_evidence_retain_until(TIMESTAMPTZ, INTEGER);
