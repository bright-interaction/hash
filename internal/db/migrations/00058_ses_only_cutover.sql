-- +goose Up
-- This release provides only the SES ceremony. Older Hash builds could seed
-- active AES/QES routing rules and could persist a higher routing_tier on a
-- draft. Carrying either state forward would make otherwise valid documents
-- deterministically unsendable, while silently changing it would rewrite an
-- owner's assurance instruction. Fail the cutover until the owner explicitly
-- deactivates those rules and resets every non-terminal document to SES.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM eidas_routing_rules
        WHERE active AND required_tier IN ('AES', 'QES')
    ) THEN
        RAISE EXCEPTION 'SES-only cutover requires explicit owner deactivation of every active AES/QES routing rule';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM documents
        WHERE routing_tier IN ('AES', 'QES')
          AND deleted_at IS NULL
          AND status NOT IN ('completed', 'declined', 'voided', 'expired')
    ) THEN
        RAISE EXCEPTION 'SES-only cutover requires explicit owner reset of every non-terminal AES/QES document';
    END IF;
END $$;
-- +goose StatementEnd

-- Defense in depth: runtime APIs already reject activating higher-tier rules
-- and setting higher-tier drafts. Persist the release capability boundary in
-- PostgreSQL as well so a forgotten future call-site cannot revive them.
ALTER TABLE eidas_routing_rules
    ADD CONSTRAINT eidas_routing_rules_active_ses_only
    CHECK (NOT active OR required_tier = 'SES');

-- Preserve terminal/deleted historical rows exactly as recorded, but prevent
-- every draft or active ceremony from claiming an unavailable assurance tier.
ALTER TABLE documents
    ADD CONSTRAINT documents_nonterminal_routing_tier_ses_only
    CHECK (
        routing_tier = 'SES'
        OR deleted_at IS NOT NULL
        OR status IN ('completed', 'declined', 'voided', 'expired')
    );

-- +goose Down
ALTER TABLE documents
    DROP CONSTRAINT IF EXISTS documents_nonterminal_routing_tier_ses_only;
ALTER TABLE eidas_routing_rules
    DROP CONSTRAINT IF EXISTS eidas_routing_rules_active_ses_only;
