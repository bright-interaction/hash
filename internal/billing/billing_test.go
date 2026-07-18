// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package billing

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestMockProvider_CreateCheckoutReturnsRedirect(t *testing.T) {
	p := MockProvider{}
	res, err := p.CreateCheckout(context.Background(), CheckoutInput{
		OrgID:      uuid.New(),
		OrgEmail:   "ops@example.com",
		OrgName:    "Test Org",
		PlanSlug:   "pro",
		PriceCents: 4900,
		Currency:   "EUR",
		Interval:   "monthly",
		ReturnURL:  "https://hash.example/settings/billing",
		WebhookURL: "https://hash.example/webhooks/billing/secret",
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !strings.HasPrefix(res.ProviderCustomerID, "mock_cust_") {
		t.Errorf("customer id wrong: %q", res.ProviderCustomerID)
	}
	if !strings.HasPrefix(res.ProviderSubscriptionID, "mock_sub_") {
		t.Errorf("subscription id wrong: %q", res.ProviderSubscriptionID)
	}
	if !strings.Contains(res.CheckoutURL, "plan=pro") {
		t.Errorf("checkout url missing plan param: %s", res.CheckoutURL)
	}
}

func TestMockProvider_ParseWebhookHandlesEmptyBody(t *testing.T) {
	p := MockProvider{}
	ev, err := p.ParseWebhook(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if ev.Kind != "subscription.created" {
		t.Errorf("default kind wrong: %q", ev.Kind)
	}
}

func TestMockProvider_ParseWebhookHandlesJSON(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"kind":                     "invoice.paid",
		"provider_subscription_id": "mock_sub_abc",
		"provider_payment_id":      "mock_pay_def",
		"amount_cents":             4900,
		"currency":                 "EUR",
		"status":                   "paid",
	})
	p := MockProvider{}
	ev, err := p.ParseWebhook(context.Background(), body, nil)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if ev.Kind != "invoice.paid" {
		t.Errorf("kind = %q", ev.Kind)
	}
	if ev.ProviderPaymentID != "mock_pay_def" || ev.ProviderSubscriptionID != "mock_sub_abc" {
		t.Errorf("ids wrong: %#v", ev)
	}
	if ev.AmountCents != 4900 || ev.Currency != "EUR" {
		t.Errorf("amount/currency wrong: %#v", ev)
	}
}

func TestMollieProvider_ParseWebhookExtractsPaymentID(t *testing.T) {
	// Mollie posts form-encoded bodies; we extract id= and dereference.
	// The dereference itself we can't run without a real API key, so
	// just verify the parser doesn't choke and surfaces the right error.
	p := NewMollieProvider("", "https://api.mollie.invalid/v2", "secret")
	_, err := p.ParseWebhook(context.Background(), []byte("id=tr_test"), map[string]string{
		"X-Hash-Mollie-Path-Secret": "secret",
	})
	if err == nil {
		t.Fatal("expected error from network dereference, got nil")
	}
	if !strings.Contains(err.Error(), "verify payment") {
		t.Errorf("expected verify-payment error, got: %v", err)
	}
}

func TestMollieProvider_ParseWebhookRejectsBadPathSecret(t *testing.T) {
	p := NewMollieProvider("test", "https://api.mollie.invalid/v2", "correct-secret")
	_, err := p.ParseWebhook(context.Background(), []byte("id=tr_test"), map[string]string{
		"X-Hash-Mollie-Path-Secret": "wrong-secret",
	})
	if err != ErrInvalidWebhook {
		t.Errorf("expected ErrInvalidWebhook, got: %v", err)
	}
}

func TestMollieProvider_ParseWebhookMissingID(t *testing.T) {
	p := NewMollieProvider("test", "https://api.mollie.invalid/v2", "secret")
	_, err := p.ParseWebhook(context.Background(), []byte("not-a-payment-id"), nil)
	if err == nil {
		t.Fatal("expected error for missing id")
	}
}

func TestFormatCents(t *testing.T) {
	cases := map[int]string{
		0:     "0.00",
		1:     "0.01",
		99:    "0.99",
		100:   "1.00",
		4900:  "49.00",
		12345: "123.45",
	}
	for cents, want := range cases {
		got := formatCents(cents)
		if got != want {
			t.Errorf("formatCents(%d) = %q want %q", cents, got, want)
		}
	}
}

func TestParseCents(t *testing.T) {
	cases := map[string]int{
		"0.00":   0,
		"0.99":   99,
		"49.00":  4900,
		"123.45": 12345,
	}
	for in, want := range cases {
		got := parseCents(in)
		if got != want {
			t.Errorf("parseCents(%q) = %d want %d", in, got, want)
		}
	}
}
