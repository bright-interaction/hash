-- +goose Up

-- A Mollie recurring subscription cannot be created before its initial
-- sequenceType=first payment has completed and produced a valid mandate.  Keep
-- that checkout lifecycle separate from org_subscriptions: the latter is the
-- entitlement record and must only contain an actual provider subscription.
CREATE TABLE billing_checkout_activations (
    activation_key           UUID PRIMARY KEY,
    org_id                   UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    plan_id                  UUID NOT NULL REFERENCES billing_plans(id),
    provider                 TEXT NOT NULL,
    interval                 TEXT NOT NULL CHECK (interval IN ('monthly', 'yearly')),
    amount_cents             INT NOT NULL CHECK (amount_cents > 0),
    currency                 TEXT NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    state                    TEXT NOT NULL DEFAULT 'intent'
                             CHECK (state IN (
                                 'intent', 'creating_payment', 'payment_pending',
                                 'payment_paid', 'subscription_pending', 'active',
                                 'failed'
                             )),
    provider_customer_id     TEXT,
    provider_payment_id      TEXT,
    provider_mandate_id      TEXT,
    provider_subscription_id TEXT,
    checkout_url             TEXT,
    paid_at                  TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A webhook can arrive after Mollie committed the payment but before our
    -- POST response was saved. It may bind the payment ID without a checkout
    -- URL; a later provider reconciliation can fill the URL if still usable.
    CHECK (checkout_url IS NULL OR provider_payment_id IS NOT NULL),
    CHECK (state NOT IN ('payment_pending', 'payment_paid', 'subscription_pending', 'active')
           OR (provider_customer_id IS NOT NULL AND provider_payment_id IS NOT NULL)),
    CHECK (state NOT IN ('payment_paid', 'subscription_pending', 'active')
           OR (provider_mandate_id IS NOT NULL AND paid_at IS NOT NULL)),
    CHECK (state <> 'active' OR (provider_subscription_id IS NOT NULL AND paid_at IS NOT NULL))
);

CREATE UNIQUE INDEX billing_checkout_one_open_per_org_idx
    ON billing_checkout_activations(org_id)
    WHERE state IN ('intent', 'creating_payment', 'payment_pending', 'payment_paid', 'subscription_pending');
CREATE UNIQUE INDEX billing_checkout_provider_payment_idx
    ON billing_checkout_activations(provider, provider_payment_id)
    WHERE provider_payment_id IS NOT NULL;
CREATE UNIQUE INDEX billing_checkout_provider_subscription_idx
    ON billing_checkout_activations(provider, provider_subscription_id)
    WHERE provider_subscription_id IS NOT NULL;

-- Runtime deliberately hard-disables AES/QES until identity proof is bound to
-- the signed digest.  Keep the plan catalogue honest on upgraded databases
-- while preserving every unrelated feature key.
UPDATE billing_plans
SET features_json = jsonb_set(
                        jsonb_set(features_json, '{aes}', 'false'::jsonb, true),
                        '{qes}', 'false'::jsonb, true
                    ),
    description = CASE slug
        WHEN 'pro' THEN 'Daily e-signing for one team. Branding + evidence bundles.'
        WHEN 'enterprise' THEN 'Unlimited usage + white-label and SSO.'
        ELSE description
    END
WHERE slug IN ('pro', 'enterprise');

-- +goose Down
DROP INDEX IF EXISTS billing_checkout_provider_subscription_idx;
DROP INDEX IF EXISTS billing_checkout_provider_payment_idx;
DROP INDEX IF EXISTS billing_checkout_one_open_per_org_idx;
DROP TABLE IF EXISTS billing_checkout_activations;
