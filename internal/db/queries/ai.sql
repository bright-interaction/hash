-- name: InsertAICompletionAudit :one
INSERT INTO ai_completion_audit (
    org_id, document_id, actor_user_id, provider, model,
    prompt_name, prompt_version, shield_active,
    input_tokens, output_tokens, latency_ms, success, error,
    transfer_jurisdiction
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8,
    $9, $10, $11, $12, $13,
    $14
) RETURNING *;

-- name: GetOrgAISettings :one
SELECT * FROM org_ai_settings WHERE org_id = $1;

-- name: UpsertOrgAISettings :one
INSERT INTO org_ai_settings (
    org_id, provider, base_url, model, api_key_ct, key_last4, enabled, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, now()
)
ON CONFLICT (org_id) DO UPDATE SET
    provider   = EXCLUDED.provider,
    base_url   = EXCLUDED.base_url,
    model      = EXCLUDED.model,
    api_key_ct = EXCLUDED.api_key_ct,
    key_last4  = EXCLUDED.key_last4,
    enabled    = EXCLUDED.enabled,
    updated_at = now()
RETURNING *;

-- name: DeleteOrgAISettings :exec
DELETE FROM org_ai_settings WHERE org_id = $1;

