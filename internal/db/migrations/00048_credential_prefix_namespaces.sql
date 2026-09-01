-- +goose Up
-- Credential prefixes are routing identifiers, not secrets. The historical
-- shared 32-bit namespace could nevertheless collide: api_keys was not unique,
-- and an org key could shadow a document token because authentication queried
-- the tables in order. Refuse to carry an ambiguous legacy database forward,
-- then constrain newly minted credentials to disjoint 128-bit namespaces.

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM api_keys a
        JOIN document_agent_tokens d ON d.prefix = a.key_prefix
    ) THEN
        RAISE EXCEPTION 'credential prefix collision across api_keys and document_agent_tokens; rotate the colliding credentials before migration';
    END IF;
END $$;
-- +goose StatementEnd

CREATE UNIQUE INDEX api_keys_key_prefix_unique_idx ON api_keys (key_prefix);

ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_routable_prefix_check
    CHECK (key_prefix ~ '^([0-9a-f]{8}|a[0-9a-f]{32})$');

ALTER TABLE document_agent_tokens
    ADD CONSTRAINT document_agent_tokens_routable_prefix_check
    CHECK (prefix ~ '^([0-9a-f]{8}|d[0-9a-f]{32})$');

-- +goose Down
ALTER TABLE document_agent_tokens
    DROP CONSTRAINT IF EXISTS document_agent_tokens_routable_prefix_check;
ALTER TABLE api_keys
    DROP CONSTRAINT IF EXISTS api_keys_routable_prefix_check;
DROP INDEX IF EXISTS api_keys_key_prefix_unique_idx;
