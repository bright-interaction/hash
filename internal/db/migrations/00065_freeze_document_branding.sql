-- +goose Up
-- Signer, final-PDF, and certificate rendering use the complete per-document
-- branding snapshot materialized by Send. Keep that snapshot coupled to the
-- document lifecycle in PostgreSQL: application checks alone cannot prevent a
-- concurrent or privileged application-role write from changing legal output.
--
-- The write-excluding lock makes the legacy inventory check and trigger
-- installation one cutover. An old server may finish before this transaction
-- acquires the lock; once it does, no unguarded branding mutation can commit in
-- the gap before the trigger exists.
LOCK TABLE documents, document_branding_override IN ACCESS EXCLUSIVE MODE;

-- Keep the cutover inventory and the draft-exit trigger on one exact predicate.
-- This mirrors branding.NormaliseFontFamily: at most 256 bytes, ASCII-safe
-- family components, single spaces inside a family, and ", " between families.
-- The explicit negated-character check prevents a terminal newline from being
-- accepted by regex end-anchor behavior.
-- +goose StatementBegin
CREATE FUNCTION hash_document_has_valid_frozen_branding(target_document_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (
        SELECT 1
          FROM public.document_branding_override b
         WHERE b.document_id = target_document_id
           AND b.primary_hex IS NOT NULL
           AND b.accent_hex IS NOT NULL
           AND b.surface_hex IS NOT NULL
           AND b.text_hex IS NOT NULL
           AND b.muted_hex IS NOT NULL
           AND b.logo_url IS NOT NULL
           AND b.logo_alt IS NOT NULL
           AND b.font_heading IS NOT NULL
           AND b.font_body IS NOT NULL
           AND b.signature_color IS NOT NULL
           AND b.primary_hex ~ '^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$'
           AND b.accent_hex ~ '^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$'
           AND b.surface_hex ~ '^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$'
           AND b.text_hex ~ '^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$'
           AND b.muted_hex ~ '^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$'
           AND b.signature_color ~ '^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$'
           AND octet_length(b.font_heading) BETWEEN 1 AND 256
           AND octet_length(b.font_body) BETWEEN 1 AND 256
           AND b.font_heading ~ '[^[:space:]]'
           AND b.font_body ~ '[^[:space:]]'
           AND b.font_heading !~ '[^A-Za-z0-9_, -]'
           AND b.font_body !~ '[^A-Za-z0-9_, -]'
           AND b.font_heading ~ '^[A-Za-z0-9_-]+( [A-Za-z0-9_-]+)*(, [A-Za-z0-9_-]+( [A-Za-z0-9_-]+)*)*$'
           AND b.font_body ~ '^[A-Za-z0-9_-]+( [A-Za-z0-9_-]+)*(, [A-Za-z0-9_-]+( [A-Za-z0-9_-]+)*)*$'
           AND b.logo_url = ''
    )
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM documents d
        WHERE d.status <> 'draft'
	      AND NOT hash_document_has_valid_frozen_branding(d.id)
    ) THEN
		RAISE EXCEPTION 'frozen branding cutover requires a complete, valid, logo-free snapshot for every non-draft document';
	END IF;
	IF EXISTS (
		SELECT 1 FROM org_branding WHERE logo_url <> ''
	) OR EXISTS (
		SELECT 1
		  FROM document_branding_override
		 WHERE logo_url IS NOT NULL AND logo_url <> ''
	) THEN
		RAISE EXCEPTION 'frozen branding cutover requires every organization and document logo to be empty';
    END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION hash_guard_document_branding_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_document_id UUID;
    document_status TEXT;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.document_id IS DISTINCT FROM OLD.document_id THEN
        RAISE EXCEPTION 'document branding snapshot identity is immutable';
    END IF;

    IF TG_OP = 'DELETE' THEN
        target_document_id := OLD.document_id;
    ELSE
        target_document_id := NEW.document_id;
    END IF;

    -- This row lock serializes branding edits with Send's document FOR UPDATE
    -- lock. If Send wins, this statement observes sealing after the wait and
    -- fails; if the edit wins, Send observes and freezes the committed draft
    -- values before it can leave draft.
    SELECT status
      INTO document_status
      FROM documents
     WHERE id = target_document_id
       FOR KEY SHARE;

    IF NOT FOUND THEN
        -- The documents FK uses ON DELETE CASCADE. Its internal delete reaches
        -- this trigger after the parent row is no longer visible; permitting
        -- that one path preserves hard deletion of already-authorized drafts.
        -- A direct child mutation still sees the parent and is checked below.
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'document branding snapshot requires an existing document';
    END IF;

    IF document_status <> 'draft' THEN
        RAISE EXCEPTION 'document branding snapshot is immutable outside draft state';
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER document_branding_snapshot_lifecycle_guard
BEFORE INSERT OR UPDATE OR DELETE ON document_branding_override
FOR EACH ROW
EXECUTE FUNCTION hash_guard_document_branding_snapshot();

-- +goose StatementBegin
CREATE FUNCTION hash_require_frozen_branding_before_draft_exit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    requires_snapshot BOOLEAN;
BEGIN
    IF TG_OP = 'INSERT' THEN
        requires_snapshot := NEW.status <> 'draft';
    ELSE
        requires_snapshot := OLD.status = 'draft' AND NEW.status <> 'draft';
    END IF;

    IF requires_snapshot AND NOT hash_document_has_valid_frozen_branding(NEW.id) THEN
        RAISE EXCEPTION 'document cannot leave draft without a complete, valid, canonical, logo-free branding snapshot';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER documents_frozen_branding_before_draft_exit
BEFORE INSERT OR UPDATE OF status ON documents
FOR EACH ROW
EXECUTE FUNCTION hash_require_frozen_branding_before_draft_exit();

-- +goose Down
-- Removing the database guard after any document has left draft would reopen a
-- mutation path for signer and terminal evidence. The v61 epoch commitment and
-- document.sent event survive changes_requested -> draft, so rollback checks
-- durable ceremony history as well as current status under a write fence.
LOCK TABLE documents, document_branding_override, events IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM documents
         WHERE status <> 'draft'
            OR article13_notice_epoch_v61_committed
    ) OR EXISTS (
        SELECT 1 FROM events WHERE kind = 'document.sent'
    ) THEN
		RAISE EXCEPTION 'cannot roll back frozen branding guard after a document has left draft or committed a send ceremony';
    END IF;
END $$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS documents_frozen_branding_before_draft_exit ON documents;
DROP FUNCTION IF EXISTS hash_require_frozen_branding_before_draft_exit();
DROP TRIGGER IF EXISTS document_branding_snapshot_lifecycle_guard ON document_branding_override;
DROP FUNCTION IF EXISTS hash_guard_document_branding_snapshot();
DROP FUNCTION IF EXISTS hash_document_has_valid_frozen_branding(UUID);
