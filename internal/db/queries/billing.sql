-- name: ListActiveBillingPlans :many
SELECT * FROM billing_plans WHERE active = TRUE ORDER BY sort_order, monthly_price_cents;

-- name: GetBillingPlanBySlug :one
SELECT * FROM billing_plans WHERE slug = $1;

-- name: GetBillingPlanByID :one
SELECT * FROM billing_plans WHERE id = $1;

-- name: GetOrgSubscription :one
SELECT * FROM org_subscriptions WHERE org_id = $1;

-- name: GetOpenBillingCheckoutForOrg :one
SELECT * FROM billing_checkout_activations
WHERE org_id = $1
  AND state IN ('intent', 'creating_payment', 'payment_pending', 'payment_paid', 'subscription_pending')
LIMIT 1;

-- name: GetLatestBillingCheckoutForOrg :one
SELECT * FROM billing_checkout_activations
WHERE org_id = $1
ORDER BY created_at DESC, activation_key DESC
LIMIT 1;

-- name: GetBillingCheckoutByKey :one
SELECT * FROM billing_checkout_activations
WHERE activation_key = $1;

-- name: GetBillingCheckoutByPayment :one
SELECT * FROM billing_checkout_activations
WHERE provider = $1 AND provider_payment_id = $2
LIMIT 1;

-- name: GetBillingCheckoutBySubscription :one
SELECT * FROM billing_checkout_activations
WHERE provider = $1 AND provider_subscription_id = $2
LIMIT 1;

-- name: InsertBillingCheckoutIntent :one
INSERT INTO billing_checkout_activations (
    activation_key, org_id, plan_id, provider, interval, amount_cents, currency, state
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, 'intent'
)
ON CONFLICT (activation_key) DO UPDATE SET updated_at = now()
WHERE billing_checkout_activations.org_id = EXCLUDED.org_id
  AND billing_checkout_activations.plan_id = EXCLUDED.plan_id
  AND billing_checkout_activations.provider = EXCLUDED.provider
  AND billing_checkout_activations.interval = EXCLUDED.interval
  AND billing_checkout_activations.amount_cents = EXCLUDED.amount_cents
  AND billing_checkout_activations.currency = EXCLUDED.currency
RETURNING *;

-- name: MarkBillingCheckoutCreatingPayment :one
UPDATE billing_checkout_activations
SET state = 'creating_payment', updated_at = now()
WHERE activation_key = $1
  AND state IN ('intent', 'creating_payment')
RETURNING *;

-- name: SetBillingCheckoutPayment :one
UPDATE billing_checkout_activations
SET provider_customer_id = $2,
    provider_payment_id = $3,
    checkout_url = $4,
    state = 'payment_pending',
    updated_at = now()
WHERE activation_key = $1
  AND state IN ('creating_payment', 'payment_pending')
  AND (provider_customer_id IS NULL OR provider_customer_id = $2)
  AND (provider_payment_id IS NULL OR provider_payment_id = $3)
  AND (checkout_url IS NULL OR checkout_url = $4)
RETURNING *;

-- name: BindBillingCheckoutPaymentFromWebhook :one
UPDATE billing_checkout_activations
SET provider_customer_id = $2,
    provider_payment_id = $3,
    state = 'payment_pending',
    updated_at = now()
WHERE activation_key = $1
  AND state IN ('creating_payment', 'payment_pending')
  AND (provider_customer_id IS NULL OR provider_customer_id = $2)
  AND (provider_payment_id IS NULL OR provider_payment_id = $3)
RETURNING *;

-- name: MarkBillingCheckoutPaymentPaid :one
UPDATE billing_checkout_activations
SET state = CASE
        WHEN state = 'active' THEN 'active'
        ELSE 'payment_paid'
    END,
    paid_at = COALESCE(paid_at, $4),
    provider_mandate_id = COALESCE(provider_mandate_id, $5),
    updated_at = now()
WHERE provider = $1
  AND provider_payment_id = $2
  AND provider_customer_id = $3
  AND state IN ('payment_pending', 'payment_paid', 'subscription_pending', 'active')
  AND (paid_at IS NULL OR paid_at = $4)
  AND (provider_mandate_id IS NULL OR provider_mandate_id = $5)
RETURNING *;

-- name: MarkBillingCheckoutSubscriptionPending :one
UPDATE billing_checkout_activations
SET state = CASE WHEN state = 'active' THEN 'active' ELSE 'subscription_pending' END,
    updated_at = now()
WHERE activation_key = $1
  AND state IN ('payment_paid', 'subscription_pending', 'active')
RETURNING *;

-- name: MarkBillingCheckoutFailed :one
UPDATE billing_checkout_activations
SET state = 'failed', updated_at = now()
WHERE activation_key = $1
  AND state IN ('intent', 'creating_payment', 'payment_pending')
RETURNING *;

-- name: ActivateBillingCheckout :one
WITH activated AS (
    UPDATE billing_checkout_activations AS checkout
    SET provider_subscription_id = sqlc.arg(input_subscription_id),
        state = 'active',
        paid_at = COALESCE(checkout.paid_at, sqlc.arg(period_start)),
        updated_at = now()
    WHERE checkout.activation_key = sqlc.arg(activation_key)
      AND checkout.provider_customer_id = sqlc.arg(input_customer_id)
      AND checkout.provider_payment_id = sqlc.arg(input_payment_id)
      AND checkout.state IN ('payment_paid', 'subscription_pending', 'active')
      AND (checkout.provider_subscription_id IS NULL OR checkout.provider_subscription_id = sqlc.arg(input_subscription_id))
      AND NOT EXISTS (
          SELECT 1 FROM billing_invoices conflict
          WHERE conflict.provider = checkout.provider
            AND conflict.provider_payment_id = checkout.provider_payment_id
            AND conflict.org_id <> checkout.org_id
      )
    RETURNING checkout.*
), upserted AS (
    INSERT INTO org_subscriptions (
        org_id, plan_id, provider, provider_customer_id, provider_subscription_id,
        status, current_period_start, current_period_end, cancel_at_period_end, trial_ends_at
    )
    SELECT
        org_id, plan_id, provider, provider_customer_id, provider_subscription_id,
        'active', sqlc.arg(period_start), sqlc.arg(period_end), FALSE, NULL
    FROM activated
    ON CONFLICT (org_id) DO UPDATE SET
        plan_id = EXCLUDED.plan_id,
        provider = EXCLUDED.provider,
        provider_customer_id = EXCLUDED.provider_customer_id,
        provider_subscription_id = EXCLUDED.provider_subscription_id,
        status = 'active',
        current_period_start = EXCLUDED.current_period_start,
        current_period_end = EXCLUDED.current_period_end,
        cancel_at_period_end = FALSE,
        trial_ends_at = NULL,
        updated_at = now()
    RETURNING *
), invoiced AS (
    INSERT INTO billing_invoices (
        org_id, subscription_id, provider, provider_payment_id, status, amount_cents,
        currency, description, period_start, period_end, paid_at, hosted_invoice_url, pdf_url
    )
    SELECT
        a.org_id, s.id, a.provider, a.provider_payment_id, 'paid', a.amount_cents,
        a.currency, sqlc.arg(description), sqlc.arg(period_start), sqlc.arg(period_end),
        sqlc.arg(period_start), sqlc.narg(hosted_invoice_url), sqlc.narg(pdf_url)
    FROM activated a
    JOIN upserted s ON s.org_id = a.org_id
    ON CONFLICT (provider, provider_payment_id) DO UPDATE SET
        subscription_id = EXCLUDED.subscription_id,
        status = 'paid',
        amount_cents = EXCLUDED.amount_cents,
        currency = EXCLUDED.currency,
        description = EXCLUDED.description,
        period_start = EXCLUDED.period_start,
        period_end = EXCLUDED.period_end,
        paid_at = EXCLUDED.paid_at,
        hosted_invoice_url = EXCLUDED.hosted_invoice_url,
        pdf_url = EXCLUDED.pdf_url
    WHERE billing_invoices.org_id = EXCLUDED.org_id
    RETURNING subscription_id
)
SELECT s.*
FROM upserted s
JOIN invoiced i ON i.subscription_id = s.id;

-- name: ApplyRecurringBillingPayment :one
WITH eligible AS (
    SELECT a.*
    FROM billing_checkout_activations a
    WHERE a.activation_key = sqlc.arg(activation_key)
      AND a.state = 'active'
      AND a.provider_customer_id = sqlc.arg(input_customer_id)
      AND a.provider_subscription_id = sqlc.arg(input_subscription_id)
      AND NOT EXISTS (
          SELECT 1 FROM billing_invoices conflict
          WHERE conflict.provider = a.provider
            AND conflict.provider_payment_id = sqlc.arg(provider_payment_id)
            AND conflict.org_id <> a.org_id
      )
), updated AS (
    UPDATE org_subscriptions s
    SET status = 'active',
        current_period_start = sqlc.arg(period_start),
        current_period_end = sqlc.arg(period_end),
        updated_at = now()
    FROM eligible a
    WHERE s.org_id = a.org_id
      AND s.plan_id = a.plan_id
      AND s.provider = a.provider
      AND s.provider_customer_id = a.provider_customer_id
      AND s.provider_subscription_id = a.provider_subscription_id
      AND (s.current_period_start IS NULL OR sqlc.arg(period_start) >= s.current_period_start)
    RETURNING s.*
), invoiced AS (
    INSERT INTO billing_invoices (
        org_id, subscription_id, provider, provider_payment_id, status, amount_cents,
        currency, description, period_start, period_end, paid_at, hosted_invoice_url, pdf_url
    )
    SELECT
        a.org_id, s.id, a.provider, sqlc.arg(provider_payment_id), 'paid', a.amount_cents,
        a.currency, sqlc.arg(description), sqlc.arg(period_start), sqlc.arg(period_end),
        sqlc.arg(period_start), sqlc.narg(hosted_invoice_url), sqlc.narg(pdf_url)
    FROM eligible a
    JOIN updated s ON s.org_id = a.org_id
    ON CONFLICT (provider, provider_payment_id) DO UPDATE SET
        subscription_id = EXCLUDED.subscription_id,
        status = 'paid',
        amount_cents = EXCLUDED.amount_cents,
        currency = EXCLUDED.currency,
        description = EXCLUDED.description,
        period_start = EXCLUDED.period_start,
        period_end = EXCLUDED.period_end,
        paid_at = EXCLUDED.paid_at,
        hosted_invoice_url = EXCLUDED.hosted_invoice_url,
        pdf_url = EXCLUDED.pdf_url
    WHERE billing_invoices.org_id = EXCLUDED.org_id
    RETURNING subscription_id
)
SELECT s.*
FROM updated s
JOIN invoiced i ON i.subscription_id = s.id;

-- name: UpsertOrgSubscription :one
INSERT INTO org_subscriptions (
    org_id, plan_id, provider, provider_customer_id, provider_subscription_id,
    status, current_period_start, current_period_end, cancel_at_period_end, trial_ends_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)
ON CONFLICT (org_id) DO UPDATE SET
    plan_id                  = EXCLUDED.plan_id,
    provider                 = EXCLUDED.provider,
    provider_customer_id     = COALESCE(EXCLUDED.provider_customer_id, org_subscriptions.provider_customer_id),
    provider_subscription_id = COALESCE(EXCLUDED.provider_subscription_id, org_subscriptions.provider_subscription_id),
    status                   = EXCLUDED.status,
    current_period_start     = COALESCE(EXCLUDED.current_period_start, org_subscriptions.current_period_start),
    current_period_end       = COALESCE(EXCLUDED.current_period_end, org_subscriptions.current_period_end),
    cancel_at_period_end     = EXCLUDED.cancel_at_period_end,
    trial_ends_at            = COALESCE(EXCLUDED.trial_ends_at, org_subscriptions.trial_ends_at),
    updated_at               = now()
RETURNING *;

-- name: SetSubscriptionCancelAtPeriodEnd :one
UPDATE org_subscriptions
SET cancel_at_period_end = $2, updated_at = now()
WHERE org_id = $1
RETURNING *;

-- name: GetSubscriptionByProvider :one
SELECT * FROM org_subscriptions
WHERE provider = $1 AND provider_subscription_id = $2
LIMIT 1;

-- name: InsertBillingInvoice :one
INSERT INTO billing_invoices (
    org_id, subscription_id, provider, provider_payment_id, status, amount_cents,
    currency, description, period_start, period_end, paid_at, hosted_invoice_url, pdf_url
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
)
ON CONFLICT (provider, provider_payment_id) DO UPDATE SET
    subscription_id     = COALESCE(EXCLUDED.subscription_id, billing_invoices.subscription_id),
    status              = EXCLUDED.status,
    amount_cents        = EXCLUDED.amount_cents,
    currency            = EXCLUDED.currency,
    paid_at             = EXCLUDED.paid_at,
    hosted_invoice_url  = EXCLUDED.hosted_invoice_url,
    pdf_url             = EXCLUDED.pdf_url
WHERE billing_invoices.org_id = EXCLUDED.org_id
RETURNING *;

-- name: ListBillingInvoicesForOrg :many
SELECT * FROM billing_invoices
WHERE org_id = $1
ORDER BY created_at DESC
LIMIT $2;

-- name: CountDocumentsInPeriodForOrg :one
SELECT COUNT(*) FROM documents d
WHERE d.org_id = $1
  AND d.created_at >= $2
  AND d.created_at < $3
  AND NOT EXISTS (
      SELECT 1
      FROM compliance_baselines cb
      WHERE cb.org_id = d.org_id
        AND (cb.records_doc_id = d.id OR cb.privacy_notice_id = d.id)
  );

-- name: LockBillingUsageForOrg :exec
-- Every quota-consuming authoring transaction uses the same lock key as the
-- automation API. Collisions only serialize unrelated orgs; authorization and
-- usage queries remain independently org-scoped.
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(org_id)::text, 63001));

-- name: CountBillingUsageInPeriodForOrg :one
SELECT
    (SELECT COUNT(*) FROM documents d
      WHERE d.org_id = sqlc.arg(org_id)
        AND d.created_at >= sqlc.arg(period_start)
        AND d.created_at < sqlc.arg(period_end)
        AND NOT EXISTS (
            SELECT 1
            FROM compliance_baselines cb
            WHERE cb.org_id = d.org_id
              AND (cb.records_doc_id = d.id OR cb.privacy_notice_id = d.id)
        ))::BIGINT AS documents_used,
    (SELECT COUNT(*) FROM recipients r
      JOIN documents d ON d.id = r.document_id
      WHERE d.org_id = sqlc.arg(org_id)
        AND r.created_at >= sqlc.arg(period_start)
        AND r.created_at < sqlc.arg(period_end)
        AND NOT EXISTS (
            SELECT 1
            FROM compliance_baselines cb
            WHERE cb.org_id = d.org_id
              AND (cb.records_doc_id = d.id OR cb.privacy_notice_id = d.id)
        ))::BIGINT AS recipients_used;

-- name: ListSubscriptionsOverQuotaWarning :many
WITH usage AS (
    SELECT
        os.id AS subscription_id,
        os.org_id,
        os.current_period_start,
        os.current_period_end,
        bp.slug AS plan_slug,
        bp.name AS plan_name,
        bp.document_quota_monthly,
        bp.recipient_quota_monthly,
        (SELECT COUNT(*) FROM documents d
            WHERE d.org_id = os.org_id
              AND d.created_at >= os.current_period_start
              AND d.created_at < COALESCE(os.current_period_end, now())
              AND NOT EXISTS (
                  SELECT 1
                  FROM compliance_baselines cb
                  WHERE cb.org_id = d.org_id
                    AND (cb.records_doc_id = d.id OR cb.privacy_notice_id = d.id)
              ))::INT AS documents_used,
        (SELECT COUNT(*) FROM recipients r
            JOIN documents d2 ON d2.id = r.document_id
            WHERE d2.org_id = os.org_id
              AND r.created_at >= os.current_period_start
              AND r.created_at < COALESCE(os.current_period_end, now())
              AND NOT EXISTS (
                  SELECT 1
                  FROM compliance_baselines cb
                  WHERE cb.org_id = d2.org_id
                    AND (cb.records_doc_id = d2.id OR cb.privacy_notice_id = d2.id)
              ))::INT AS recipients_used,
        os.last_quota_warning_sent_at
    FROM org_subscriptions os
    JOIN billing_plans bp ON bp.id = os.plan_id
    WHERE os.status IN ('trialing', 'active')
      AND os.current_period_start IS NOT NULL
)
SELECT
    subscription_id,
    org_id,
    current_period_start,
    current_period_end,
    plan_slug,
    plan_name,
    document_quota_monthly,
    recipient_quota_monthly,
    documents_used,
    recipients_used
FROM usage
WHERE (last_quota_warning_sent_at IS NULL
       OR last_quota_warning_sent_at < current_period_start)
  AND (
        (document_quota_monthly > 0 AND documents_used * 100 >= document_quota_monthly * $1::INT)
     OR (recipient_quota_monthly > 0 AND recipients_used * 100 >= recipient_quota_monthly * $1::INT)
  );

-- name: MarkQuotaWarningSent :exec
UPDATE org_subscriptions
SET last_quota_warning_sent_at = now()
WHERE id = $1;
