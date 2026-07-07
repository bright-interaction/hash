-- +goose Up
-- Per-org "bring your own AI" provider config. When a row exists and is
-- enabled, the AI runtime routes that org's completions to the org's own
-- provider + key instead of the instance default; every other org is
-- unaffected. The API key is stored AES-256-GCM encrypted at rest under the
-- instance shield key (HASH_AI_SHIELD_KEY); the plaintext is never
-- returned by the API. key_last4 keeps a non-sensitive hint so the UI can
-- show which key is configured without decrypting.
CREATE TABLE org_ai_settings (
    org_id      UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    provider    TEXT NOT NULL,
    base_url    TEXT NOT NULL DEFAULT '',
    model       TEXT NOT NULL DEFAULT '',
    api_key_ct  BYTEA NOT NULL,
    key_last4   TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE org_ai_settings;
