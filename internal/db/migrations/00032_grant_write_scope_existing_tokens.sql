-- +goose Up
-- Token write-scope is now enforced: a token without the 'write' scope can no
-- longer call MCP write tools. Enforcement was never active before, so every
-- existing key/token was effectively write-capable. Grant 'write' to all
-- existing rows so the rollout is non-breaking; a token must be deliberately
-- created read-only ([read]) to become read-only. The create endpoints default
-- to [read,write] to preserve the prior write-by-default behaviour, with
-- read-only as an explicit opt-in.
-- The scope vocabulary is granular (write:authoring, write:workflow); grant
-- both to every existing token that has neither a write:* scope nor admin, so
-- prior write-by-default behaviour is preserved.
UPDATE api_keys
  SET scopes = scopes || ARRAY['write:authoring', 'write:workflow']
  WHERE NOT ('admin' = ANY(scopes))
    AND NOT ('write:authoring' = ANY(scopes))
    AND NOT ('write:workflow' = ANY(scopes));
-- document_agent_tokens use the [read, write, sign] vocabulary; grant plain
-- write to every existing token that lacks it.
UPDATE document_agent_tokens
  SET scopes = array_append(scopes, 'write')
  WHERE NOT ('admin' = ANY(scopes))
    AND NOT ('write' = ANY(scopes));

-- +goose Down
-- Not cleanly reversible: we cannot distinguish a 'write' scope granted by this
-- backfill from one set deliberately. The column is unchanged, so this is a
-- no-op down rather than a guess that could strip legitimate write scopes.
SELECT 1;
