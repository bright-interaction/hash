-- name: ListActiveBillingPlans :many
SELECT * FROM billing_plans WHERE active = TRUE ORDER BY sort_order, monthly_price_cents;

-- name: GetBillingPlanBySlug :one
SELECT * FROM billing_plans WHERE slug = $1;

-- name: GetBillingPlanByID :one
SELECT * FROM billing_plans WHERE id = $1;

-- name: GetOrgSubscription :one
SELECT * FROM org_subscriptions WHERE org_id = $1;

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
    status              = EXCLUDED.status,
    amount_cents        = EXCLUDED.amount_cents,
    paid_at             = EXCLUDED.paid_at,
    hosted_invoice_url  = EXCLUDED.hosted_invoice_url,
    pdf_url             = EXCLUDED.pdf_url
RETURNING *;

-- name: ListBillingInvoicesForOrg :many
SELECT * FROM billing_invoices
WHERE org_id = $1
ORDER BY created_at DESC
LIMIT $2;

-- name: CountDocumentsInPeriodForOrg :one
SELECT COUNT(*) FROM documents
WHERE org_id = $1
  AND created_at >= $2
  AND created_at < $3;

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
              AND d.created_at < COALESCE(os.current_period_end, now()))::INT AS documents_used,
        (SELECT COUNT(*) FROM recipients r
            JOIN documents d2 ON d2.id = r.document_id
            WHERE d2.org_id = os.org_id
              AND r.created_at >= os.current_period_start
              AND r.created_at < COALESCE(os.current_period_end, now()))::INT AS recipients_used,
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
