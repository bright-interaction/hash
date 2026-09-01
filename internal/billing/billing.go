// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package billing implements v1.1 subscription management for Hash
// orgs. The Provider interface abstracts away the payment processor
// (Mollie in production, mock for dev/e2e). The Engine wraps the
// Provider + sqlc queries: it persists subscription state, enforces
// plan quotas at authoring and send boundaries, and processes provider webhook
// events idempotently.
//
// Quota model: each plan declares document_quota_monthly +
// recipient_quota_monthly (0 = unlimited). EnforceDocumentQuota counts
// documents and recipients created in the current period (rolling 30-day for
// free orgs, current_period_start for active subs). Counted authoring inserts
// are serialized per org and rejected atomically when the prospective row
// would exceed quota. Send repeats the check before recipient mail fan-out.
package billing

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Provider is the strategy interface for payment processors. Real impls:
// MollieProvider (production), MockProvider (dev/e2e).
type Provider interface {
	Name() string
	// CreateCheckout creates (or reconciles) a customer and a
	// sequenceType=first payment. It must not create the recurring
	// subscription: that is only allowed after the paid webhook proves a
	// valid mandate exists.
	CreateCheckout(ctx context.Context, in CheckoutInput) (*CheckoutResult, error)
	// CreateSubscription creates (or reconciles) the actual recurring
	// subscription after the first payment was independently dereferenced.
	CreateSubscription(ctx context.Context, in SubscriptionInput) (*SubscriptionResult, error)
	// CancelSubscription tells the provider to stop renewing the
	// subscription at the current period end. Active period stays
	// usable until expiry.
	CancelSubscription(ctx context.Context, providerCustomerID, providerSubscriptionID string) error
	// ParseWebhook validates a provider webhook payload + returns the
	// canonical event the engine acts on. Returns ErrInvalidWebhook
	// for bad signatures so the handler can 401.
	ParseWebhook(ctx context.Context, raw []byte, headers map[string]string) (*WebhookEvent, error)
}

// CheckoutInput is what the engine hands a Provider when creating a
// checkout session.
type CheckoutInput struct {
	ActivationKey uuid.UUID
	OrgID         uuid.UUID
	OrgEmail      string
	OrgName       string
	PlanSlug      string
	PriceCents    int
	Currency      string
	Interval      string // 'monthly' | 'yearly'
	ReturnURL     string
	WebhookURL    string
	Description   string
	// ExistingCustomerID avoids creating another provider customer for an
	// org that already has a subscription. Reconcile asks the provider to
	// search by the durable activation metadata before issuing another POST.
	ExistingCustomerID string
	Reconcile          bool
}

// CheckoutResult is what a Provider returns. ProviderCustomerID +
// ProviderSubscriptionID may be empty if the provider creates them
// asynchronously (Mollie does this; the webhook fills them in).
type CheckoutResult struct {
	ProviderCustomerID string
	ProviderPaymentID  string
	CheckoutURL        string
}

// SubscriptionInput is emitted only after a strictly-correlated first
// payment is paid and carries a valid mandate.
type SubscriptionInput struct {
	ActivationKey      uuid.UUID
	OrgID              uuid.UUID
	PlanSlug           string
	ProviderCustomerID string
	MandateID          string
	PriceCents         int
	Currency           string
	Interval           string
	WebhookURL         string
	Description        string
}

type SubscriptionResult struct {
	ProviderSubscriptionID string
}

// WebhookEvent is the canonical shape every provider's webhooks
// normalise to. The engine routes on Kind.
type WebhookEvent struct {
	Kind                   string // 'subscription.created' | 'subscription.updated' | 'invoice.paid' | 'invoice.failed' | 'subscription.cancelled'
	ProviderCustomerID     string
	ProviderSubscriptionID string
	ProviderPaymentID      string
	ActivationKey          uuid.UUID
	OrgID                  uuid.UUID
	PlanSlug               string
	Interval               string
	SequenceType           string
	MandateID              string
	Status                 string
	AmountCents            int
	Currency               string
	PeriodStart            *time.Time
	PeriodEnd              *time.Time
	PaidAt                 *time.Time
	ProviderCreatedAt      *time.Time
	CheckoutURL            string
	HostedInvoiceURL       string
	PDFURL                 string
}

var (
	ErrDisabled                = errors.New("billing: feature disabled on this instance")
	ErrPlanNotFound            = errors.New("billing: plan not found")
	ErrInvalidWebhook          = errors.New("billing: invalid webhook signature")
	ErrQuotaExceeded           = errors.New("billing: plan quota exceeded")
	ErrSubscriptionNone        = errors.New("billing: no subscription for org")
	ErrInvalidCheckout         = errors.New("billing: invalid checkout request")
	ErrCheckoutInProgress      = errors.New("billing: another checkout is already in progress")
	ErrWebhookCorrelation      = errors.New("billing: webhook does not match a persisted checkout")
	ErrEntitlementUnavailable  = errors.New("billing: entitlement check temporarily unavailable")
	ErrCheckoutPaymentTerminal = errors.New("billing: checkout payment is terminal")
)

type CheckoutPaymentTerminalError struct{ Status string }

func (e *CheckoutPaymentTerminalError) Error() string {
	return ErrCheckoutPaymentTerminal.Error() + ": " + e.Status
}

func (e *CheckoutPaymentTerminalError) Is(target error) bool {
	return target == ErrCheckoutPaymentTerminal
}

// EntitlementUnavailableError distinguishes an unavailable quota decision
// from a known quota exhaustion. Callers must surface it as retryable 5xx,
// never as Payment Required.
type EntitlementUnavailableError struct {
	Stage string
	Err   error
}

func (e *EntitlementUnavailableError) Error() string {
	if e == nil || e.Stage == "" {
		return ErrEntitlementUnavailable.Error()
	}
	return ErrEntitlementUnavailable.Error() + ": " + e.Stage
}

func (e *EntitlementUnavailableError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *EntitlementUnavailableError) Is(target error) bool {
	return target == ErrEntitlementUnavailable
}
