-- +goose Up

-- v1.1 Mollie billing. Per-org subscriptions, plan-based document
-- quotas, invoice persistence keyed by Mollie payment IDs. Behind a
-- feature flag (HASH_BILLING_PROVIDER): the 'mock' provider keeps
-- the surface callable for dev + e2e without a Mollie account; the
-- 'mollie' provider hits api.mollie.com for real charges.

CREATE TABLE billing_plans (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug                    TEXT NOT NULL UNIQUE,
    name                    TEXT NOT NULL,
    description             TEXT NOT NULL DEFAULT '',
    monthly_price_cents     INT NOT NULL DEFAULT 0,
    yearly_price_cents      INT NOT NULL DEFAULT 0,
    currency                TEXT NOT NULL DEFAULT 'EUR',
    document_quota_monthly  INT NOT NULL DEFAULT 0,   -- 0 = unlimited
    recipient_quota_monthly INT NOT NULL DEFAULT 0,   -- 0 = unlimited
    features_json           JSONB NOT NULL DEFAULT '{}'::jsonb,
    active                  BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order              INT NOT NULL DEFAULT 0,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE org_subscriptions (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                   UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE UNIQUE,
    plan_id                  UUID NOT NULL REFERENCES billing_plans(id),
    provider                 TEXT NOT NULL DEFAULT 'mock',   -- 'mock' | 'mollie'
    provider_customer_id     TEXT,
    provider_subscription_id TEXT,
    status                   TEXT NOT NULL DEFAULT 'trialing',
                              -- trialing | active | past_due | cancelled | unpaid
    current_period_start     TIMESTAMPTZ,
    current_period_end       TIMESTAMPTZ,
    cancel_at_period_end     BOOLEAN NOT NULL DEFAULT FALSE,
    trial_ends_at            TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_org_subscriptions_status ON org_subscriptions(status);
CREATE INDEX idx_org_subscriptions_provider_sub
    ON org_subscriptions(provider, provider_subscription_id)
    WHERE provider_subscription_id IS NOT NULL;

CREATE TABLE billing_invoices (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    subscription_id     UUID REFERENCES org_subscriptions(id) ON DELETE SET NULL,
    provider            TEXT NOT NULL,
    provider_payment_id TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'open',
                         -- open | paid | failed | refunded | cancelled
    amount_cents        INT NOT NULL,
    currency            TEXT NOT NULL DEFAULT 'EUR',
    description         TEXT NOT NULL DEFAULT '',
    period_start        TIMESTAMPTZ,
    period_end          TIMESTAMPTZ,
    paid_at             TIMESTAMPTZ,
    hosted_invoice_url  TEXT,
    pdf_url             TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_billing_invoices_org ON billing_invoices(org_id, created_at DESC);
CREATE UNIQUE INDEX idx_billing_invoices_provider
    ON billing_invoices(provider, provider_payment_id);

-- Seed the three starter plans. Idempotent on slug.
INSERT INTO billing_plans (slug, name, description, monthly_price_cents, yearly_price_cents, currency, document_quota_monthly, recipient_quota_monthly, features_json, sort_order)
VALUES
    ('free', 'Free', 'For trying Hash. SES tier only.',
     0, 0, 'EUR',
     5, 10,
     '{"qes":false,"aes":false,"branding":false,"evidence_bundle":false,"audit_timeline":true,"mcp":false}'::jsonb,
     10),
    ('pro', 'Pro', 'Daily e-signing for one team. AES + branding + evidence bundles.',
     4900, 49000, 'EUR',
     50, 200,
     '{"qes":false,"aes":true,"branding":true,"evidence_bundle":true,"audit_timeline":true,"mcp":true}'::jsonb,
     20),
    ('enterprise', 'Enterprise', 'BankID via Idura + unlimited usage + white-label.',
     29900, 299000, 'EUR',
     0, 0,
     '{"qes":true,"aes":true,"branding":true,"evidence_bundle":true,"audit_timeline":true,"mcp":true,"white_label":true,"sso":true}'::jsonb,
     30)
ON CONFLICT (slug) DO NOTHING;

-- +goose Down

DROP INDEX IF EXISTS idx_billing_invoices_provider;
DROP INDEX IF EXISTS idx_billing_invoices_org;
DROP TABLE IF EXISTS billing_invoices;
DROP INDEX IF EXISTS idx_org_subscriptions_provider_sub;
DROP INDEX IF EXISTS idx_org_subscriptions_status;
DROP TABLE IF EXISTS org_subscriptions;
DROP TABLE IF EXISTS billing_plans;
