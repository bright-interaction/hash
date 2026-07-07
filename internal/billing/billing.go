// Package billing implements v1.1 subscription management for Hash
// orgs. The Provider interface abstracts away the payment processor
// (Mollie in production, mock for dev/e2e). The Engine wraps the
// Provider + sqlc queries: it persists subscription state, enforces
// plan quotas at the send boundary, and processes provider webhook
// events idempotently.
//
// Quota model: each plan declares document_quota_monthly +
// recipient_quota_monthly (0 = unlimited). EnforceDocumentQuota counts
// documents created in the current period (rolling 30-day for trialing
// orgs, current_period_start for active subs) and refuses sends when
// over. The check happens BEFORE the recipient mailer fan-out so a
// blocked org sees a 402 Payment Required, not a half-finished send.
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
	// CreateCheckout starts a hosted checkout for the given plan +
	// returns the URL the signer's browser should navigate to. The
	// provider stores its own customer/subscription IDs against the
	// org via the webhook callback so we don't pollute the engine
	// with provider-specific state machines.
	CreateCheckout(ctx context.Context, in CheckoutInput) (*CheckoutResult, error)
	// CancelSubscription tells the provider to stop renewing the
	// subscription at the current period end. Active period stays
	// usable until expiry.
	CancelSubscription(ctx context.Context, providerSubscriptionID string) error
	// ParseWebhook validates a provider webhook payload + returns the
	// canonical event the engine acts on. Returns ErrInvalidWebhook
	// for bad signatures so the handler can 401.
	ParseWebhook(ctx context.Context, raw []byte, headers map[string]string) (*WebhookEvent, error)
}

// CheckoutInput is what the engine hands a Provider when creating a
// checkout session.
type CheckoutInput struct {
	OrgID       uuid.UUID
	OrgEmail    string
	OrgName     string
	PlanSlug    string
	PriceCents  int
	Currency    string
	Interval    string // 'monthly' | 'yearly'
	ReturnURL   string
	WebhookURL  string
	Description string
}

// CheckoutResult is what a Provider returns. ProviderCustomerID +
// ProviderSubscriptionID may be empty if the provider creates them
// asynchronously (Mollie does this; the webhook fills them in).
type CheckoutResult struct {
	ProviderCustomerID     string
	ProviderSubscriptionID string
	CheckoutURL            string
}

// WebhookEvent is the canonical shape every provider's webhooks
// normalise to. The engine routes on Kind.
type WebhookEvent struct {
	Kind                   string // 'subscription.created' | 'subscription.updated' | 'invoice.paid' | 'invoice.failed' | 'subscription.cancelled'
	ProviderCustomerID     string
	ProviderSubscriptionID string
	ProviderPaymentID      string
	OrgID                  uuid.UUID
	Status                 string
	AmountCents            int
	Currency               string
	PeriodStart            *time.Time
	PeriodEnd              *time.Time
	HostedInvoiceURL       string
	PDFURL                 string
}

var (
	ErrDisabled         = errors.New("billing: feature disabled on this instance")
	ErrPlanNotFound     = errors.New("billing: plan not found")
	ErrInvalidWebhook   = errors.New("billing: invalid webhook signature")
	ErrQuotaExceeded    = errors.New("billing: plan quota exceeded")
	ErrSubscriptionNone = errors.New("billing: no subscription for org")
)
