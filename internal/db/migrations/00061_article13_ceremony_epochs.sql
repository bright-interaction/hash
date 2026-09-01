-- +goose Up
-- Article 13 evidence is bound to a send ceremony by both its schema and the
-- exact documents.sent_at value. Refuse an upgrade while an interactive
-- pre-cutover ceremony has no valid, chain-committed document.sent marker;
-- inventing that marker during migration would misstate what the signer saw.

-- +goose StatementBegin
CREATE FUNCTION hash_article13_canonical_sent_at(value TIMESTAMPTZ)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
BEGIN
    IF NOT isfinite(value) THEN
        RETURN NULL;
    END IF;
    RETURN rtrim(
        rtrim(to_char(value AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'), '0'),
        '.'
    ) || 'Z';
END;
$$;
-- +goose StatementEnd

-- Keep this registry in lockstep with internal/article13's immutable schema
-- registry. A future schema is not trusted merely because an event names it.
-- +goose StatementBegin
CREATE FUNCTION hash_article13_marker_is_valid(payload JSONB, payload_hashed BYTEA)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
    committed_payload JSONB;
    marker_schema TEXT;
    marker_sent_at_text TEXT;
    marker_sent_at TIMESTAMPTZ;
BEGIN
    IF payload IS NULL OR jsonb_typeof(payload) <> 'object' OR payload_hashed IS NULL THEN
        RETURN FALSE;
    END IF;
    committed_payload := convert_from(payload_hashed, 'UTF8')::jsonb;
    IF committed_payload IS DISTINCT FROM payload THEN
        RETURN FALSE;
    END IF;
    IF jsonb_typeof(payload -> 'required_notice_schema') IS DISTINCT FROM 'string'
       OR jsonb_typeof(payload -> 'required_notice_sent_at') IS DISTINCT FROM 'string' THEN
        RETURN FALSE;
    END IF;
    marker_schema := payload ->> 'required_notice_schema';
    IF marker_schema IS NULL OR marker_schema NOT IN ('hash-a13-2026-08-31') THEN
        RETURN FALSE;
    END IF;
    marker_sent_at_text := payload ->> 'required_notice_sent_at';
    IF marker_sent_at_text IS NULL THEN
        RETURN FALSE;
    END IF;
    marker_sent_at := marker_sent_at_text::timestamptz;
    RETURN COALESCE(
        hash_article13_canonical_sent_at(marker_sent_at) = marker_sent_at_text,
        FALSE
    );
EXCEPTION
    WHEN OTHERS THEN
        RETURN FALSE;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION hash_article13_marker_matches(
    payload JSONB,
    payload_hashed BYTEA,
    expected_schema TEXT,
    expected_sent_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
BEGIN
    IF expected_schema IS NULL OR btrim(expected_schema) = ''
       OR expected_sent_at IS NULL OR NOT isfinite(expected_sent_at)
       OR NOT hash_article13_marker_is_valid(payload, payload_hashed) THEN
        RETURN FALSE;
    END IF;
    RETURN COALESCE(
        payload ->> 'required_notice_schema' = expected_schema
        AND payload ->> 'required_notice_sent_at' = hash_article13_canonical_sent_at(expected_sent_at),
        FALSE
    );
END;
$$;
-- +goose StatementEnd

-- Hold a single cutover snapshot from the inventory checks through every
-- column/constraint/trigger install. Without these locks an old writer could
-- create an unmarked ceremony or sealing intent after the guard passed.
LOCK TABLE documents IN ACCESS EXCLUSIVE MODE;
LOCK TABLE send_sealing_intents IN ACCESS EXCLUSIVE MODE;
LOCK TABLE events IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM documents WHERE status = 'sealing')
       OR EXISTS (SELECT 1 FROM send_sealing_intents) THEN
        RAISE EXCEPTION 'Article 13 epoch cutover requires every in-flight send sealing operation to be drained before migration';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM documents d
        LEFT JOIN LATERAL (
            SELECT e.payload_json, e.payload_hashed, e.row_hash
            FROM events e
            WHERE e.document_id = d.id
              AND e.org_id = d.org_id
              AND e.kind = 'document.sent'
              AND e.recipient_id IS NULL
            ORDER BY e.created_at DESC, e.id DESC
            LIMIT 1
        ) marker ON TRUE
        WHERE d.deleted_at IS NULL
          AND d.status IN ('sent', 'in_progress', 'changes_requested')
          AND (
              d.sent_at IS NULL
              OR marker.payload_json IS NULL
              OR octet_length(marker.row_hash) IS DISTINCT FROM 32
              OR NOT hash_article13_marker_is_valid(marker.payload_json, marker.payload_hashed)
              OR marker.payload_json ->> 'required_notice_sent_at'
                    <> hash_article13_canonical_sent_at(d.sent_at)
          )
    ) THEN
        RAISE EXCEPTION 'Article 13 cutover requires every active sent/in_progress/changes_requested ceremony to have a valid document.sent marker tied to authoritative sent_at; drain or terminate the pre-cutover inventory';
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE documents
    -- The epoch is a durable high-water mark. Revision clears the active
    -- sent_at but never this value, so a resend remains monotonic even if the
    -- database clock moves backwards.
    ADD COLUMN article13_notice_epoch_at TIMESTAMPTZ,
    ADD COLUMN article13_notice_schema TEXT NOT NULL DEFAULT '',
    -- A post-cutover send makes rollback one-way: an older writer would discard
    -- the high-water mark on the next revise/resend cycle.
    ADD COLUMN article13_notice_epoch_v61_committed BOOLEAN NOT NULL DEFAULT FALSE;

-- The send intent owns the next ceremony epoch before the first irreversible
-- retention API call. Its Object Lock deadline is derived from this exact
-- anchor in the same INSERT, so a crash/retry can change neither value.
ALTER TABLE send_sealing_intents
    ADD COLUMN article13_notice_epoch_at TIMESTAMPTZ NOT NULL,
    ALTER COLUMN retain_until SET NOT NULL,
    ADD CONSTRAINT send_sealing_article13_epoch_valid CHECK (
        isfinite(article13_notice_epoch_at)
    ),
    ADD CONSTRAINT send_sealing_deadline_matches_article13_epoch CHECK (
        retain_until = hash_evidence_retain_until(article13_notice_epoch_at, 7)
    );

-- Recover the greatest supported, byte-committed ceremony epoch for every
-- document, including a draft revised before this release. Event chronology
-- alone is insufficient because a pre-cutover application/DB clock rollback
-- could make the newest marker's sent_at older than an earlier ceremony.
-- MATERIALIZED keeps guarded JSON validation ahead of the timestamp cast.
WITH valid_send AS MATERIALIZED (
    SELECT e.document_id, e.org_id, e.created_at, e.id,
           e.payload_json ->> 'required_notice_schema' AS marker_schema,
           e.payload_json ->> 'required_notice_sent_at' AS marker_sent_at
    FROM events e
    WHERE e.document_id IS NOT NULL
      AND e.kind = 'document.sent'
      AND e.recipient_id IS NULL
      AND octet_length(e.row_hash) = 32
      AND hash_article13_marker_is_valid(e.payload_json, e.payload_hashed)
),
greatest_send AS MATERIALIZED (
    SELECT DISTINCT ON (document_id, org_id)
           document_id, org_id, marker_schema, marker_sent_at
    FROM valid_send
    ORDER BY document_id, org_id, marker_sent_at::timestamptz DESC,
             created_at DESC, id DESC
)
UPDATE documents d
SET article13_notice_schema = marker.marker_schema,
    article13_notice_epoch_at = marker.marker_sent_at::timestamptz
FROM greatest_send marker
WHERE marker.document_id = d.id
  AND marker.org_id = d.org_id;

-- A terminal legacy row may have no marker, but its retained sent_at is still
-- a useful monotonic lower bound. The blank schema preserves its unbound
-- provenance instead of relabeling historical evidence as Article 13 aware.
UPDATE documents
SET article13_notice_epoch_at = sent_at
WHERE article13_notice_epoch_at IS NULL
  AND sent_at IS NOT NULL;

ALTER TABLE documents
    ADD CONSTRAINT documents_article13_notice_schema_supported CHECK (
        article13_notice_schema IN ('', 'hash-a13-2026-08-31')
    ),
    ADD CONSTRAINT documents_article13_notice_epoch_shape CHECK (
        (article13_notice_epoch_at IS NULL AND article13_notice_schema = '')
        OR (
            article13_notice_epoch_at IS NOT NULL
            AND isfinite(article13_notice_epoch_at)
        )
    ),
    ADD CONSTRAINT documents_article13_active_ceremony_bound CHECK (
        status NOT IN ('sent', 'in_progress', 'changes_requested', 'finalizing')
        OR (
            sent_at IS NOT NULL
            AND article13_notice_schema <> ''
            AND article13_notice_epoch_at = sent_at
        )
    ),
    ADD CONSTRAINT documents_article13_editable_has_no_active_epoch CHECK (
        status NOT IN ('draft', 'sealing') OR sent_at IS NULL
    ),
    ADD CONSTRAINT documents_article13_v61_commitment_complete CHECK (
        NOT article13_notice_epoch_v61_committed
        OR (
            article13_notice_epoch_at IS NOT NULL
            AND article13_notice_schema <> ''
        )
    );

-- +goose StatementBegin
CREATE FUNCTION reject_article13_notice_epoch_rewrite()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.article13_notice_epoch_v61_committed
       AND NOT NEW.article13_notice_epoch_v61_committed THEN
        RAISE EXCEPTION 'documents.article13_notice_epoch_v61_committed is irreversible';
    END IF;

    IF NEW.article13_notice_epoch_at IS DISTINCT FROM OLD.article13_notice_epoch_at THEN
        IF OLD.status <> 'sealing' OR NEW.status <> 'sent'
           OR NEW.article13_notice_epoch_at IS NULL
           OR (OLD.article13_notice_epoch_at IS NOT NULL
               AND NEW.article13_notice_epoch_at <= OLD.article13_notice_epoch_at) THEN
            RAISE EXCEPTION 'documents.article13_notice_epoch_at may only advance during sealing-to-sent completion';
        END IF;
    END IF;

    IF NEW.article13_notice_schema IS DISTINCT FROM OLD.article13_notice_schema
       AND NEW.article13_notice_epoch_at IS NOT DISTINCT FROM OLD.article13_notice_epoch_at THEN
        RAISE EXCEPTION 'documents.article13_notice_schema cannot change without a new send epoch';
    END IF;

    IF OLD.sent_at IS NOT NULL AND NEW.sent_at IS NULL
       AND NOT (OLD.status = 'changes_requested' AND NEW.status = 'draft') THEN
        RAISE EXCEPTION 'documents.sent_at may only clear during an evidence-safe revision';
    END IF;
    IF OLD.sent_at IS NOT NULL AND NEW.sent_at IS NOT NULL
       AND NEW.sent_at IS DISTINCT FROM OLD.sent_at THEN
        RAISE EXCEPTION 'documents.sent_at is immutable within a ceremony';
    END IF;
    IF OLD.sent_at IS NULL AND NEW.sent_at IS NOT NULL
       AND NOT (OLD.status = 'sealing' AND NEW.status = 'sent'
                AND NEW.article13_notice_epoch_v61_committed) THEN
        RAISE EXCEPTION 'documents.sent_at may only be allocated by durable send completion';
    END IF;
    IF OLD.status = 'sealing' AND NEW.status = 'sent'
       AND NOT NEW.article13_notice_epoch_v61_committed THEN
        RAISE EXCEPTION 'post-cutover send must commit the durable Article 13 epoch';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER documents_article13_notice_epoch_immutable
BEFORE UPDATE OF status, sent_at, article13_notice_epoch_at,
                 article13_notice_schema, article13_notice_epoch_v61_committed
ON documents
FOR EACH ROW
EXECUTE FUNCTION reject_article13_notice_epoch_rewrite();

-- +goose StatementBegin
CREATE FUNCTION reject_send_sealing_article13_epoch_rewrite()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.article13_notice_epoch_at IS DISTINCT FROM OLD.article13_notice_epoch_at THEN
        RAISE EXCEPTION 'send_sealing_intents.article13_notice_epoch_at is immutable';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER send_sealing_article13_epoch_immutable
BEFORE UPDATE OF article13_notice_epoch_at ON send_sealing_intents
FOR EACH ROW
EXECUTE FUNCTION reject_send_sealing_article13_epoch_rewrite();

-- The state row is updated before its audit row in the same transaction. A
-- deferred constraint trigger checks the final transaction snapshot so either
-- both the active state and its exact marker commit, or neither does.
-- +goose StatementBegin
CREATE FUNCTION require_active_article13_notice_marker()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.deleted_at IS NULL
       AND NEW.status IN ('sent', 'in_progress', 'changes_requested')
       AND NOT EXISTS (
           SELECT 1
           FROM (
               SELECT e.payload_json, e.payload_hashed, e.row_hash, e.recipient_id
               FROM events e
               WHERE e.document_id = NEW.id
                 AND e.org_id = NEW.org_id
                 AND e.kind = 'document.sent'
               ORDER BY e.created_at DESC, e.id DESC
               LIMIT 1
           ) marker
           WHERE marker.recipient_id IS NULL
             AND octet_length(marker.row_hash) = 32
             AND hash_article13_marker_matches(
                 marker.payload_json,
                 marker.payload_hashed,
                 NEW.article13_notice_schema,
                 NEW.sent_at
             )
       ) THEN
        RAISE EXCEPTION 'active document lacks a valid Article 13 marker for its authoritative ceremony epoch';
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

CREATE CONSTRAINT TRIGGER documents_active_article13_notice_marker
AFTER INSERT OR UPDATE ON documents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION require_active_article13_notice_marker();

-- +goose Down
-- Keep the one-way rollback check and the destructive DDL in one write-fenced
-- critical section. A concurrent sender must not commit between them.
LOCK TABLE documents IN ACCESS EXCLUSIVE MODE;
LOCK TABLE send_sealing_intents IN ACCESS EXCLUSIVE MODE;
LOCK TABLE events IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM send_sealing_intents)
       OR EXISTS (
        SELECT 1 FROM documents
        WHERE article13_notice_epoch_v61_committed
    ) THEN
        RAISE EXCEPTION 'cannot roll back Article 13 ceremony epochs while an intent or post-cutover send commitment exists';
    END IF;
END $$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS documents_active_article13_notice_marker ON documents;
DROP FUNCTION IF EXISTS require_active_article13_notice_marker();
DROP TRIGGER IF EXISTS send_sealing_article13_epoch_immutable ON send_sealing_intents;
DROP FUNCTION IF EXISTS reject_send_sealing_article13_epoch_rewrite();
DROP TRIGGER IF EXISTS documents_article13_notice_epoch_immutable ON documents;
DROP FUNCTION IF EXISTS reject_article13_notice_epoch_rewrite();

ALTER TABLE send_sealing_intents
    DROP CONSTRAINT IF EXISTS send_sealing_deadline_matches_article13_epoch,
    DROP CONSTRAINT IF EXISTS send_sealing_article13_epoch_valid,
    ALTER COLUMN retain_until DROP NOT NULL,
    DROP COLUMN IF EXISTS article13_notice_epoch_at;

ALTER TABLE documents
    DROP CONSTRAINT IF EXISTS documents_article13_v61_commitment_complete,
    DROP CONSTRAINT IF EXISTS documents_article13_editable_has_no_active_epoch,
    DROP CONSTRAINT IF EXISTS documents_article13_active_ceremony_bound,
    DROP CONSTRAINT IF EXISTS documents_article13_notice_epoch_shape,
    DROP CONSTRAINT IF EXISTS documents_article13_notice_schema_supported,
    DROP COLUMN IF EXISTS article13_notice_epoch_v61_committed,
    DROP COLUMN IF EXISTS article13_notice_schema,
    DROP COLUMN IF EXISTS article13_notice_epoch_at;

DROP FUNCTION IF EXISTS hash_article13_marker_matches(JSONB, BYTEA, TEXT, TIMESTAMPTZ);
DROP FUNCTION IF EXISTS hash_article13_marker_is_valid(JSONB, BYTEA);
DROP FUNCTION IF EXISTS hash_article13_canonical_sent_at(TIMESTAMPTZ);
