// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package billing

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMollieCreateCheckoutCreatesFirstPaymentNotSubscription(t *testing.T) {
	orgID := uuid.New()
	activationKey := uuid.New()
	metadata := checkoutMetadata(activationKey, orgID, "pro", "monthly")
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("authorization header = %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/customers":
			if r.Method != http.MethodPost || r.Header.Get("Idempotency-Key") != "hash-customer-"+orgID.String() {
				t.Errorf("customer request method/key = %s/%q", r.Method, r.Header.Get("Idempotency-Key"))
			}
			var body struct {
				Metadata map[string]string `json:"metadata"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Metadata["org_id"] != orgID.String() {
				t.Errorf("customer org metadata = %q", body.Metadata["org_id"])
			}
			writeTestJSON(w, mollieCustomer{ID: "cst_test", Metadata: map[string]any{"org_id": orgID.String()}})
		case "/payments":
			if r.Method != http.MethodPost || r.Header.Get("Idempotency-Key") != "hash-first-"+activationKey.String() {
				t.Errorf("payment request method/key = %s/%q", r.Method, r.Header.Get("Idempotency-Key"))
			}
			var body struct {
				Amount       mollieAmount   `json:"amount"`
				CustomerID   string         `json:"customerId"`
				SequenceType string         `json:"sequenceType"`
				RedirectURL  string         `json:"redirectUrl"`
				WebhookURL   string         `json:"webhookUrl"`
				Metadata     mollieMetadata `json:"metadata"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.SequenceType != "first" || body.CustomerID != "cst_test" || body.Amount.Value != "49.00" ||
				body.Amount.Currency != "EUR" || body.Metadata != metadata || body.RedirectURL != "https://hash.example/return" ||
				body.WebhookURL != "https://hash.example/webhook" {
				t.Errorf("unexpected first payment body: %#v", body)
			}
			payment := molliePayment{
				ID: "tr_test", Status: "open", Amount: body.Amount, CustomerID: body.CustomerID,
				SequenceType: body.SequenceType, Metadata: body.Metadata,
			}
			payment.Links.Checkout.Href = "https://www.mollie.com/checkout/test"
			writeTestJSON(w, payment)
		default:
			t.Errorf("unexpected Mollie endpoint %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewMollieProvider("test-key", server.URL, "path-secret")
	provider.HTTP = server.Client()
	result, err := provider.CreateCheckout(context.Background(), CheckoutInput{
		ActivationKey: activationKey, OrgID: orgID, OrgEmail: "ops@example.test", OrgName: "Test Org",
		PlanSlug: "pro", PriceCents: 4900, Currency: "EUR", Interval: "monthly",
		ReturnURL: "https://hash.example/return", WebhookURL: "https://hash.example/webhook", Description: "Hash Pro",
	})
	if err != nil {
		t.Fatalf("CreateCheckout: %v", err)
	}
	if result.ProviderCustomerID != "cst_test" || result.ProviderPaymentID != "tr_test" ||
		result.CheckoutURL != "https://www.mollie.com/checkout/test" {
		t.Fatalf("checkout result = %#v", result)
	}
	wantCalls := []string{"POST /customers", "POST /payments"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("Mollie calls = %v, want %v (subscription must not be created yet)", calls, wantCalls)
	}
}

func TestMolliePaidWebhookDereferenceThenSubscriptionAndScopedCancel(t *testing.T) {
	orgID := uuid.New()
	activationKey := uuid.New()
	metadata := checkoutMetadata(activationKey, orgID, "pro", "monthly")
	paidAt := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/payments/tr_paid":
			writeTestJSON(w, molliePayment{
				ID: "tr_paid", Status: "paid", Amount: mollieAmount{Currency: "EUR", Value: "49.00"},
				Metadata: metadata, SequenceType: "first", CustomerID: "cst_test", MandateID: "mdt_test",
				PaidAt: paidAt.Format(time.RFC3339),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/customers/cst_test/mandates/mdt_test":
			writeTestJSON(w, map[string]any{"id": "mdt_test", "status": "valid", "customerId": "cst_test"})
		case r.Method == http.MethodGet && r.URL.Path == "/customers/cst_test/subscriptions":
			writeTestJSON(w, map[string]any{"_embedded": map[string]any{"subscriptions": []any{}}, "_links": map[string]any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/customers/cst_test/subscriptions":
			if r.Header.Get("Idempotency-Key") != "hash-subscription-"+activationKey.String() {
				t.Errorf("subscription idempotency key = %q", r.Header.Get("Idempotency-Key"))
			}
			var body struct {
				Amount   mollieAmount   `json:"amount"`
				Interval string         `json:"interval"`
				Mandate  string         `json:"mandateId"`
				Metadata mollieMetadata `json:"metadata"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Mandate != "mdt_test" {
				t.Errorf("subscription mandateId = %q", body.Mandate)
			}
			writeTestJSON(w, mollieSubscription{
				ID: "sub_test", Status: "active", CustomerID: "cst_test", Amount: body.Amount,
				Interval: body.Interval, Metadata: body.Metadata,
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/customers/cst_test/subscriptions/sub_test":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected Mollie endpoint %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewMollieProvider("test-key", server.URL, "path-secret")
	provider.HTTP = server.Client()
	event, err := provider.ParseWebhook(context.Background(), []byte("id=tr_paid"), map[string]string{
		"X-Hash-Mollie-Path-Secret": "path-secret",
	})
	if err != nil {
		t.Fatalf("ParseWebhook: %v", err)
	}
	if event.ProviderPaymentID != "tr_paid" || event.ActivationKey != activationKey || event.OrgID != orgID ||
		event.Kind != "invoice.paid" || event.PaidAt == nil || !event.PaidAt.Equal(paidAt) || event.MandateID != "mdt_test" {
		t.Fatalf("dereferenced event = %#v", event)
	}
	result, err := provider.CreateSubscription(context.Background(), SubscriptionInput{
		ActivationKey: activationKey, OrgID: orgID, PlanSlug: "pro", ProviderCustomerID: "cst_test", MandateID: "mdt_test",
		PriceCents: 4900, Currency: "EUR", Interval: "monthly", WebhookURL: "https://hash.example/webhook", Description: "Hash Pro",
	})
	if err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	if result.ProviderSubscriptionID != "sub_test" {
		t.Fatalf("subscription result = %#v", result)
	}
	if err := provider.CancelSubscription(context.Background(), "cst_test", "sub_test"); err != nil {
		t.Fatalf("CancelSubscription: %v", err)
	}
	wantCalls := []string{
		"GET /payments/tr_paid", "GET /customers/cst_test/mandates/mdt_test",
		"GET /customers/cst_test/subscriptions", "POST /customers/cst_test/subscriptions",
		"DELETE /customers/cst_test/subscriptions/sub_test",
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("Mollie calls = %v, want %v", calls, wantCalls)
	}
}

func TestMollieRejectsNonHTTPSCheckoutURL(t *testing.T) {
	in := CheckoutInput{
		ActivationKey: uuid.New(), OrgID: uuid.New(), PlanSlug: "pro", PriceCents: 4900,
		Currency: "EUR", Interval: "monthly", ReturnURL: "http://hash.example/return",
		WebhookURL: "https://hash.example/webhook",
	}
	provider := NewMollieProvider("test-key", "https://api.mollie.invalid/v2", "secret")
	if _, err := provider.CreateCheckout(context.Background(), in); !errors.Is(err, ErrInvalidCheckout) {
		t.Fatalf("CreateCheckout error = %v, want ErrInvalidCheckout", err)
	}
}

func TestMollieReconciledTerminalPaymentNeverReturnsCheckout(t *testing.T) {
	in := CheckoutInput{
		ActivationKey: uuid.New(), OrgID: uuid.New(), PlanSlug: "pro", PriceCents: 4900,
		Currency: "EUR", Interval: "monthly",
	}
	payment := molliePayment{
		ID: "tr_terminal", Status: "expired", Amount: mollieAmount{Currency: "EUR", Value: "49.00"},
		CustomerID: "cst_test", SequenceType: "first",
		Metadata: checkoutMetadata(in.ActivationKey, in.OrgID, in.PlanSlug, in.Interval),
	}
	payment.Links.Checkout.Href = "https://www.mollie.com/checkout/stale"

	if _, err := validateFirstPayment(payment, "cst_test", in); !errors.Is(err, ErrCheckoutPaymentTerminal) {
		t.Fatalf("expired payment error = %v, want ErrCheckoutPaymentTerminal", err)
	}
	payment.Status = "paid"
	if _, err := validateFirstPayment(payment, "cst_test", in); !errors.Is(err, ErrCheckoutInProgress) {
		t.Fatalf("paid payment error = %v, want ErrCheckoutInProgress", err)
	}
}

func writeTestJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
