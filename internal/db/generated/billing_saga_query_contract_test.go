// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package generated

import (
	"strings"
	"testing"
)

func TestBillingSagaQueriesFailClosed(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		fragments []string
	}{
		{
			name:  "early webhook durably binds unresolved payment identity",
			query: bindBillingCheckoutPaymentFromWebhook,
			fragments: []string{
				"state IN ('creating_payment', 'payment_pending')", "provider_customer_id IS NULL OR provider_customer_id =",
				"provider_payment_id IS NULL OR provider_payment_id =", "state = 'payment_pending'", "RETURNING",
			},
		},
		{
			name:  "paid checkpoint durably binds mandate and timestamp",
			query: markBillingCheckoutPaymentPaid,
			fragments: []string{
				"provider_mandate_id = COALESCE", "paid_at = COALESCE", "provider_mandate_id IS NULL OR provider_mandate_id =",
				"paid_at IS NULL OR paid_at =", "RETURNING",
			},
		},
		{
			name:  "latest terminal checkout can safely reuse its customer",
			query: getLatestBillingCheckoutForOrg,
			fragments: []string{
				"WHERE org_id", "ORDER BY created_at DESC", "LIMIT 1",
			},
		},
		{
			name:  "checkout intent is durable before provider work",
			query: insertBillingCheckoutIntent,
			fragments: []string{
				"billing_checkout_activations", "activation_key", "amount_cents", "currency", "'intent'", "RETURNING",
			},
		},
		{
			name:  "payment identity cannot overwrite another saga",
			query: setBillingCheckoutPayment,
			fragments: []string{
				"state IN ('creating_payment', 'payment_pending')", "provider_customer_id IS NULL OR provider_customer_id =",
				"provider_payment_id IS NULL OR provider_payment_id =", "checkout_url IS NULL OR checkout_url =", "RETURNING",
			},
		},
		{
			name:  "entitlement and paid invoice activate atomically",
			query: activateBillingCheckout,
			fragments: []string{
				"state IN ('payment_paid', 'subscription_pending', 'active')", "provider_subscription_id",
				"INSERT INTO org_subscriptions", "status = 'active'", "INSERT INTO billing_invoices", "JOIN invoiced",
				"conflict.org_id <> checkout.org_id", "billing_invoices.org_id = EXCLUDED.org_id",
			},
		},
		{
			name:  "recurring payment cannot regress or cross-bind entitlement",
			query: applyRecurringBillingPayment,
			fragments: []string{
				"conflict.org_id <> a.org_id", ">= s.current_period_start", "billing_invoices.org_id = EXCLUDED.org_id",
			},
		},
		{
			name:  "both document and recipient usage are counted",
			query: countBillingUsageInPeriodForOrg,
			fragments: []string{
				"documents_used", "recipients_used", "JOIN documents", "r.created_at >=", "r.created_at <",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, fragment := range test.fragments {
				if !strings.Contains(test.query, fragment) {
					t.Errorf("query missing safety clause %q\n%s", fragment, test.query)
				}
			}
		})
	}
}

func TestQuotaUsageExcludesComplianceBaselineDocumentsAndRecipients(t *testing.T) {
	tests := []struct {
		name               string
		query              string
		baselineExclusions int
	}{
		{name: "legacy document count", query: countDocumentsInPeriodForOrg, baselineExclusions: 1},
		{name: "enforcement document and recipient counts", query: countBillingUsageInPeriodForOrg, baselineExclusions: 2},
		{name: "warning document and recipient counts", query: listSubscriptionsOverQuotaWarning, baselineExclusions: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, fragment := range []string{"NOT EXISTS", "FROM compliance_baselines cb", "cb.records_doc_id", "cb.privacy_notice_id"} {
				if !strings.Contains(test.query, fragment) {
					t.Fatalf("billing usage query does not exclude compliance baselines via %q\n%s", fragment, test.query)
				}
			}
			if got := strings.Count(test.query, "FROM compliance_baselines cb"); got != test.baselineExclusions {
				t.Fatalf("billing usage query has %d compliance exclusions, want %d\n%s", got, test.baselineExclusions, test.query)
			}
		})
	}
}

func TestQuotaMutationAndAutomationUseTheSameOrgAdvisoryLock(t *testing.T) {
	const lockCall = "pg_advisory_xact_lock(hashtextextended($1::text, 63001))"
	for name, query := range map[string]string{
		"counted authoring": lockBillingUsageForOrg,
		"automation":        lockAutomationSignatureRequestQuota,
	} {
		if !strings.Contains(query, lockCall) {
			t.Fatalf("%s lock does not use the shared org quota key\n%s", name, query)
		}
	}
}
