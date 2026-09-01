-- +goose Up
-- White-label and per-plan SSO are not implemented runtime entitlements. Do
-- not sell feature flags that the product does not enforce or deliver. Keep
-- the implemented Enterprise differences: unlimited quotas, branding,
-- evidence bundles, audit timeline, and MCP access.
UPDATE billing_plans
SET features_json = features_json - 'white_label' - 'sso',
    description = 'Unlimited usage for larger teams. Branding, evidence bundles, and MCP.'
WHERE slug = 'enterprise';

-- +goose Down
UPDATE billing_plans
SET features_json = jsonb_set(
                        jsonb_set(features_json, '{white_label}', 'true'::jsonb, true),
                        '{sso}', 'true'::jsonb, true
                    ),
    description = 'Unlimited usage + white-label and SSO.'
WHERE slug = 'enterprise';
