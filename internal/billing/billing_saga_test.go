// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// TestHandleWebhookRecoversPaymentCommittedBeforeLocalBind covers the critical
// crash window where Mollie accepted POST /payments, but Hash died before
// SetBillingCheckoutPayment committed. The dereferenced webhook metadata must
// bind that payment to the durable activation intent before paid processing;
// otherwise a 200 response would permanently strand a paid customer.
func TestHandleWebhookRecoversPaymentCommittedBeforeLocalBind(t *testing.T) {
	activationKey := uuid.New()
	orgID := uuid.New()
	planID := uuid.New()
	paidAt := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	db := &earlyPaymentDB{
		t:             t,
		activationKey: activationKey,
		orgID:         orgID,
		planID:        planID,
		paidAt:        paidAt,
	}
	provider := &earlyPaymentProvider{t: t, event: WebhookEvent{
		Kind: "invoice.paid", ProviderCustomerID: "cst_early", ProviderPaymentID: "tr_early",
		ActivationKey: activationKey, OrgID: orgID, PlanSlug: "pro", Interval: "monthly",
		SequenceType: "first", MandateID: "mdt_early", Status: "paid", AmountCents: 4900,
		Currency: "EUR", PaidAt: &paidAt,
	}}
	engine := New(generated.New(db), provider, "https://hash.example", "https://hash.example/webhooks/billing/secret")

	if err := engine.HandleWebhook(context.Background(), []byte("id=tr_early"), nil); err != nil {
		t.Fatalf("HandleWebhook: %v", err)
	}
	if provider.subscriptionCalls != 1 {
		t.Fatalf("CreateSubscription calls = %d, want 1", provider.subscriptionCalls)
	}
	wantCalls := []string{
		"GetBillingCheckoutByPayment", "GetBillingCheckoutByKey", "GetBillingPlanByID",
		"BindBillingCheckoutPaymentFromWebhook", "GetBillingPlanByID", "MarkBillingCheckoutPaymentPaid",
		"MarkBillingCheckoutSubscriptionPending", "ActivateBillingCheckout",
	}
	if strings.Join(db.calls, ",") != strings.Join(wantCalls, ",") {
		t.Fatalf("query order = %v, want %v", db.calls, wantCalls)
	}
}

type earlyPaymentProvider struct {
	t                 *testing.T
	event             WebhookEvent
	subscriptionCalls int
}

func (*earlyPaymentProvider) Name() string { return "mollie" }

func (*earlyPaymentProvider) CreateCheckout(context.Context, CheckoutInput) (*CheckoutResult, error) {
	return nil, errors.New("unexpected CreateCheckout")
}

func (p *earlyPaymentProvider) CreateSubscription(_ context.Context, in SubscriptionInput) (*SubscriptionResult, error) {
	p.subscriptionCalls++
	if in.ActivationKey != p.event.ActivationKey || in.OrgID != p.event.OrgID ||
		in.ProviderCustomerID != p.event.ProviderCustomerID || in.MandateID != p.event.MandateID ||
		in.PlanSlug != p.event.PlanSlug || in.PriceCents != p.event.AmountCents ||
		in.Currency != p.event.Currency || in.Interval != p.event.Interval {
		p.t.Fatalf("subscription input does not match paid event: %#v", in)
	}
	return &SubscriptionResult{ProviderSubscriptionID: "sub_early"}, nil
}

func (*earlyPaymentProvider) CancelSubscription(context.Context, string, string) error {
	return errors.New("unexpected CancelSubscription")
}

func (p *earlyPaymentProvider) ParseWebhook(context.Context, []byte, map[string]string) (*WebhookEvent, error) {
	event := p.event
	return &event, nil
}

type earlyPaymentDB struct {
	t             *testing.T
	activationKey uuid.UUID
	orgID         uuid.UUID
	planID        uuid.UUID
	paidAt        time.Time
	calls         []string
}

func (*earlyPaymentDB) Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("unexpected Exec")
}

func (*earlyPaymentDB) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query")
}

func (db *earlyPaymentDB) QueryRow(_ context.Context, query string, args ...interface{}) pgx.Row {
	switch {
	case strings.Contains(query, "-- name: GetBillingCheckoutByPayment"):
		db.record("GetBillingCheckoutByPayment")
		return quotaRow{err: pgx.ErrNoRows}
	case strings.Contains(query, "-- name: GetBillingCheckoutByKey"):
		db.record("GetBillingCheckoutByKey")
		return quotaRow{values: activationValues(db.activation("creating_payment", false, false))}
	case strings.Contains(query, "-- name: GetBillingPlanByID"):
		db.record("GetBillingPlanByID")
		return quotaRow{values: planValues(db.planID)}
	case strings.Contains(query, "-- name: BindBillingCheckoutPaymentFromWebhook"):
		db.record("BindBillingCheckoutPaymentFromWebhook")
		db.requirePaymentArgs(args, 0, 1, 2)
		return quotaRow{values: activationValues(db.activation("payment_pending", true, false))}
	case strings.Contains(query, "-- name: MarkBillingCheckoutPaymentPaid"):
		db.record("MarkBillingCheckoutPaymentPaid")
		db.requirePaymentArgs(args, -1, 2, 1)
		return quotaRow{values: activationValues(db.activation("payment_paid", true, true))}
	case strings.Contains(query, "-- name: MarkBillingCheckoutSubscriptionPending"):
		db.record("MarkBillingCheckoutSubscriptionPending")
		return quotaRow{values: activationValues(db.activation("subscription_pending", true, true))}
	case strings.Contains(query, "-- name: ActivateBillingCheckout"):
		db.record("ActivateBillingCheckout")
		return quotaRow{values: []any{
			uuid.New(), db.orgID, db.planID, "mollie", text("cst_early"), text("sub_early"), "active",
			pgTime(db.paidAt), pgTime(db.paidAt.AddDate(0, 1, 0)), false, pgtype.Timestamptz{},
			pgTime(db.paidAt), pgTime(db.paidAt), pgtype.Timestamptz{},
		}}
	default:
		return quotaRow{err: fmt.Errorf("unexpected query: %.100s", query)}
	}
}

func (db *earlyPaymentDB) record(name string) { db.calls = append(db.calls, name) }

func (db *earlyPaymentDB) activation(state string, paymentBound, paid bool) generated.BillingCheckoutActivation {
	row := generated.BillingCheckoutActivation{
		ActivationKey: db.activationKey, OrgID: db.orgID, PlanID: db.planID, Provider: "mollie",
		Interval: "monthly", AmountCents: 4900, Currency: "EUR", State: state,
	}
	if paymentBound {
		row.ProviderCustomerID = text("cst_early")
		row.ProviderPaymentID = text("tr_early")
	}
	if paid {
		row.ProviderMandateID = text("mdt_early")
		row.PaidAt = pgTime(db.paidAt)
	}
	return row
}

func (db *earlyPaymentDB) requirePaymentArgs(args []interface{}, keyIndex, customerIndex, paymentIndex int) {
	db.t.Helper()
	if keyIndex >= 0 && (len(args) <= keyIndex || args[keyIndex] != db.activationKey) {
		db.t.Fatalf("activation argument = %#v, want %s", args, db.activationKey)
	}
	if len(args) <= customerIndex || args[customerIndex] != text("cst_early") ||
		len(args) <= paymentIndex || args[paymentIndex] != text("tr_early") {
		db.t.Fatalf("payment binding arguments = %#v", args)
	}
}

func activationValues(row generated.BillingCheckoutActivation) []any {
	return []any{
		row.ActivationKey, row.OrgID, row.PlanID, row.Provider, row.Interval, row.AmountCents, row.Currency, row.State,
		row.ProviderCustomerID, row.ProviderPaymentID, row.ProviderMandateID, row.ProviderSubscriptionID,
		row.CheckoutUrl, row.PaidAt, row.CreatedAt, row.UpdatedAt,
	}
}

func planValues(planID uuid.UUID) []any {
	return []any{
		planID, "pro", "Pro", "Daily e-signing", int32(4900), int32(49000), "EUR",
		int32(100), int32(500), json.RawMessage(`{"aes":false,"qes":false}`), true, int32(20), pgtype.Timestamptz{},
	}
}
