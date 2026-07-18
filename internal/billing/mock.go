// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package billing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// MockProvider is wired when HASH_BILLING_PROVIDER is empty or
// 'mock'. Behaviour:
//
//   - CreateCheckout returns a redirect URL pointing back at our own
//     webhook with a deterministic synthetic event so the checkout
//     completes locally with no external service.
//   - CancelSubscription is a no-op (the engine still flips the
//     persisted cancel_at_period_end flag).
//   - ParseWebhook accepts any payload (no signature check). Used by
//     the mock checkout return + by tests that POST synthetic events.
//
// Production never runs MockProvider; it's intentionally permissive so
// dev + e2e can exercise the billing surface end-to-end without a
// Mollie account.
type MockProvider struct{}

func (MockProvider) Name() string { return "mock" }

func (MockProvider) CreateCheckout(_ context.Context, in CheckoutInput) (*CheckoutResult, error) {
	id, err := token(12)
	if err != nil {
		return nil, err
	}
	subID := "mock_sub_" + id
	custID := "mock_cust_" + id
	// Synthesize a "completed" webhook URL that the frontend can POST
	// to right after the redirect lands so the subscription flips to
	// active without waiting on an external service.
	checkoutURL := in.ReturnURL + "?mock_subscription_id=" + subID + "&mock_customer_id=" + custID + "&plan=" + in.PlanSlug
	return &CheckoutResult{
		ProviderCustomerID:     custID,
		ProviderSubscriptionID: subID,
		CheckoutURL:            checkoutURL,
	}, nil
}

func (MockProvider) CancelSubscription(_ context.Context, _ string) error { return nil }

func (MockProvider) ParseWebhook(_ context.Context, raw []byte, _ map[string]string) (*WebhookEvent, error) {
	// Accept three shapes for mock callbacks:
	//   1. {"kind":"subscription.created","org_id":"<uuid>","plan_slug":"pro",...}
	//   2. {"kind":"invoice.paid","provider_subscription_id":"mock_sub_..."}
	//   3. an empty body (synthetic completion fired by the frontend)
	if len(raw) == 0 {
		return &WebhookEvent{Kind: "subscription.created"}, nil
	}
	var ev struct {
		Kind                   string `json:"kind"`
		OrgID                  string `json:"org_id"`
		ProviderCustomerID     string `json:"provider_customer_id"`
		ProviderSubscriptionID string `json:"provider_subscription_id"`
		ProviderPaymentID      string `json:"provider_payment_id"`
		Status                 string `json:"status"`
		AmountCents            int    `json:"amount_cents"`
		Currency               string `json:"currency"`
		PeriodStartUnix        int64  `json:"period_start_unix"`
		PeriodEndUnix          int64  `json:"period_end_unix"`
		HostedInvoiceURL       string `json:"hosted_invoice_url"`
		PDFURL                 string `json:"pdf_url"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		return &WebhookEvent{Kind: "subscription.created"}, nil
	}
	out := &WebhookEvent{
		Kind:                   ev.Kind,
		ProviderCustomerID:     ev.ProviderCustomerID,
		ProviderSubscriptionID: ev.ProviderSubscriptionID,
		ProviderPaymentID:      ev.ProviderPaymentID,
		Status:                 ev.Status,
		AmountCents:            ev.AmountCents,
		Currency:               ev.Currency,
		HostedInvoiceURL:       ev.HostedInvoiceURL,
		PDFURL:                 ev.PDFURL,
	}
	if ev.PeriodStartUnix > 0 {
		t := time.Unix(ev.PeriodStartUnix, 0).UTC()
		out.PeriodStart = &t
	}
	if ev.PeriodEndUnix > 0 {
		t := time.Unix(ev.PeriodEndUnix, 0).UTC()
		out.PeriodEnd = &t
	}
	if ev.OrgID != "" {
		if id, err := uuid.Parse(ev.OrgID); err == nil {
			out.OrgID = id
		}
	}
	if out.Kind == "" {
		out.Kind = "subscription.created"
	}
	return out, nil
}

func token(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
