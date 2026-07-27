// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// Engine is the high-level billing facade. Handlers + the send-time
// quota guard call it; nothing else reaches inside the provider.
type Engine struct {
	Queries    *generated.Queries
	Provider   Provider
	PublicURL  string
	WebhookURL string
}

// New constructs an Engine. nil provider falls back to a NoopProvider
// equivalent (MockProvider so the surface stays callable; production
// always wires Mollie).
func New(q *generated.Queries, provider Provider, publicURL, webhookURL string) *Engine {
	if provider == nil {
		provider = MockProvider{}
	}
	return &Engine{Queries: q, Provider: provider, PublicURL: publicURL, WebhookURL: webhookURL}
}

// ListPlans returns active plans in display order.
func (e *Engine) ListPlans(ctx context.Context) ([]*generated.BillingPlan, error) {
	return e.Queries.ListActiveBillingPlans(ctx)
}

// GetSubscription returns the org's current subscription, or
// ErrSubscriptionNone if none has been created. Free-tier orgs that
// have never checked out have no row; the handler maps that to a
// "free plan implied" response.
func (e *Engine) GetSubscription(ctx context.Context, orgID uuid.UUID) (*generated.OrgSubscription, error) {
	row, err := e.Queries.GetOrgSubscription(ctx, orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSubscriptionNone
	}
	if err != nil {
		return nil, err
	}
	return row, nil
}

// StartCheckout boots a Provider-side checkout for the named plan. The
// caller-facing URL is the provider's hosted UI; the engine has
// already persisted a placeholder org_subscriptions row so the webhook
// can flip status to active without race conditions.
type StartCheckoutInput struct {
	OrgID     uuid.UUID
	OrgEmail  string
	OrgName   string
	PlanSlug  string
	Interval  string // 'monthly' | 'yearly'
	ReturnURL string
}

func (e *Engine) StartCheckout(ctx context.Context, in StartCheckoutInput) (string, error) {
	if e == nil || e.Provider == nil {
		return "", ErrDisabled
	}
	plan, err := e.Queries.GetBillingPlanBySlug(ctx, in.PlanSlug)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrPlanNotFound
	}
	if err != nil {
		return "", err
	}
	price := plan.MonthlyPriceCents
	if in.Interval == "yearly" {
		price = plan.YearlyPriceCents
	}
	res, err := e.Provider.CreateCheckout(ctx, CheckoutInput{
		OrgID:       in.OrgID,
		OrgEmail:    in.OrgEmail,
		OrgName:     in.OrgName,
		PlanSlug:    in.PlanSlug,
		PriceCents:  int(price),
		Currency:    plan.Currency,
		Interval:    in.Interval,
		ReturnURL:   in.ReturnURL,
		WebhookURL:  e.WebhookURL,
		Description: "Hash " + plan.Name,
	})
	if err != nil {
		return "", err
	}
	// Persist a placeholder so webhook events have something to update, but
	// do NOT grant entitlement yet: status 'incomplete' + a NULL period means
	// PlanForOrg falls back to free until a paid invoice flips it to active.
	// Abandoning checkout therefore grants nothing (previously it wrote the
	// target plan as 'trialing' with a fabricated active window = free plan
	// forever).
	_, err = e.Queries.UpsertOrgSubscription(ctx, generated.UpsertOrgSubscriptionParams{
		OrgID:                  in.OrgID,
		PlanID:                 plan.ID,
		Provider:               e.Provider.Name(),
		ProviderCustomerID:     pgtype.Text{String: res.ProviderCustomerID, Valid: res.ProviderCustomerID != ""},
		ProviderSubscriptionID: pgtype.Text{String: res.ProviderSubscriptionID, Valid: res.ProviderSubscriptionID != ""},
		Status:                 "incomplete",
		CurrentPeriodStart:     pgtype.Timestamptz{},
		CurrentPeriodEnd:       pgtype.Timestamptz{},
		CancelAtPeriodEnd:      false,
		TrialEndsAt:            pgtype.Timestamptz{},
	})
	if err != nil {
		return "", fmt.Errorf("billing: persist subscription: %w", err)
	}
	return res.CheckoutURL, nil
}

// CancelAtPeriodEnd marks the subscription to stop renewing. The
// active period stays usable.
func (e *Engine) CancelAtPeriodEnd(ctx context.Context, orgID uuid.UUID) error {
	sub, err := e.Queries.GetOrgSubscription(ctx, orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSubscriptionNone
	}
	if err != nil {
		return err
	}
	if sub.ProviderSubscriptionID.Valid && sub.ProviderSubscriptionID.String != "" {
		if err := e.Provider.CancelSubscription(ctx, sub.ProviderSubscriptionID.String); err != nil {
			return err
		}
	}
	_, err = e.Queries.SetSubscriptionCancelAtPeriodEnd(ctx, generated.SetSubscriptionCancelAtPeriodEndParams{
		OrgID:             orgID,
		CancelAtPeriodEnd: true,
	})
	return err
}

// HandleWebhook validates + processes a provider webhook. Idempotent:
// receiving the same invoice.paid twice doesn't double-charge or
// double-insert because billing_invoices has a unique index on
// (provider, provider_payment_id).
func (e *Engine) HandleWebhook(ctx context.Context, raw []byte, headers map[string]string) error {
	ev, err := e.Provider.ParseWebhook(ctx, raw, headers)
	if err != nil {
		return err
	}
	sub, err := e.Queries.GetSubscriptionByProvider(ctx, generated.GetSubscriptionByProviderParams{
		Provider:               e.Provider.Name(),
		ProviderSubscriptionID: pgtype.Text{String: ev.ProviderSubscriptionID, Valid: ev.ProviderSubscriptionID != ""},
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		// Unknown subscription. Mock provider can fire events without
		// the engine having persisted the subscription yet, so we
		// drop these quietly so dev doesn't see noise. Real providers
		// should fire subscription.created first.
		return nil
	}
	switch ev.Kind {
	case "subscription.created", "subscription.updated":
		status := ev.Status
		if status == "" {
			status = "active"
		}
		ps, pe := periodOrDefault(ev.PeriodStart, ev.PeriodEnd)
		_, err := e.Queries.UpsertOrgSubscription(ctx, generated.UpsertOrgSubscriptionParams{
			OrgID:                  sub.OrgID,
			PlanID:                 sub.PlanID,
			Provider:               sub.Provider,
			ProviderCustomerID:     pgtype.Text{String: ev.ProviderCustomerID, Valid: ev.ProviderCustomerID != ""},
			ProviderSubscriptionID: pgtype.Text{String: ev.ProviderSubscriptionID, Valid: ev.ProviderSubscriptionID != ""},
			Status:                 status,
			CurrentPeriodStart:     ps,
			CurrentPeriodEnd:       pe,
			CancelAtPeriodEnd:      sub.CancelAtPeriodEnd,
			TrialEndsAt:            pgtype.Timestamptz{},
		})
		return err
	case "subscription.cancelled":
		_, err := e.Queries.UpsertOrgSubscription(ctx, generated.UpsertOrgSubscriptionParams{
			OrgID:                  sub.OrgID,
			PlanID:                 sub.PlanID,
			Provider:               sub.Provider,
			ProviderCustomerID:     sub.ProviderCustomerID,
			ProviderSubscriptionID: sub.ProviderSubscriptionID,
			Status:                 "cancelled",
			CurrentPeriodStart:     sub.CurrentPeriodStart,
			CurrentPeriodEnd:       sub.CurrentPeriodEnd,
			CancelAtPeriodEnd:      true,
			TrialEndsAt:            sub.TrialEndsAt,
		})
		return err
	case "invoice.paid", "invoice.failed", "invoice.updated":
		now := time.Now().UTC()
		if _, err := e.Queries.InsertBillingInvoice(ctx, generated.InsertBillingInvoiceParams{
			OrgID:             sub.OrgID,
			SubscriptionID:    pgtype.UUID{Bytes: sub.ID, Valid: true},
			Provider:          sub.Provider,
			ProviderPaymentID: ev.ProviderPaymentID,
			Status:            statusFromEventKind(ev.Kind),
			AmountCents:       int32(ev.AmountCents),
			Currency:          firstNonEmpty(ev.Currency, "EUR"),
			Description:       sub.Provider,
			PeriodStart:       toPgTime(ev.PeriodStart),
			PeriodEnd:         toPgTime(ev.PeriodEnd),
			PaidAt:            ifPaid(ev.Kind, now),
			HostedInvoiceUrl:  pgtype.Text{String: ev.HostedInvoiceURL, Valid: ev.HostedInvoiceURL != ""},
			PdfUrl:            pgtype.Text{String: ev.PDFURL, Valid: ev.PDFURL != ""},
		}); err != nil {
			return err
		}
		// Advance the subscription state machine off invoice.* events. Mollie
		// only emits invoice.* (never subscription.*), so without this a real
		// subscription would freeze in 'incomplete' forever and never grant
		// entitlement; payment failure would never downgrade.
		switch ev.Kind {
		case "invoice.paid":
			ps, pe := periodOrDefault(ev.PeriodStart, ev.PeriodEnd)
			_, err := e.Queries.UpsertOrgSubscription(ctx, generated.UpsertOrgSubscriptionParams{
				OrgID:                  sub.OrgID,
				PlanID:                 sub.PlanID,
				Provider:               sub.Provider,
				ProviderCustomerID:     sub.ProviderCustomerID,
				ProviderSubscriptionID: sub.ProviderSubscriptionID,
				Status:                 "active",
				CurrentPeriodStart:     ps,
				CurrentPeriodEnd:       pe,
				CancelAtPeriodEnd:      sub.CancelAtPeriodEnd,
				TrialEndsAt:            sub.TrialEndsAt,
			})
			return err
		case "invoice.failed":
			_, err := e.Queries.UpsertOrgSubscription(ctx, generated.UpsertOrgSubscriptionParams{
				OrgID:                  sub.OrgID,
				PlanID:                 sub.PlanID,
				Provider:               sub.Provider,
				ProviderCustomerID:     sub.ProviderCustomerID,
				ProviderSubscriptionID: sub.ProviderSubscriptionID,
				Status:                 "past_due",
				CurrentPeriodStart:     sub.CurrentPeriodStart,
				CurrentPeriodEnd:       sub.CurrentPeriodEnd,
				CancelAtPeriodEnd:      sub.CancelAtPeriodEnd,
				TrialEndsAt:            sub.TrialEndsAt,
			})
			return err
		}
		return nil
	}
	return nil
}

// periodOrDefault returns the supplied billing period, defaulting to a
// one-month window from now when the provider omitted it (the mock provider,
// and a defensive fallback for Mollie).
func periodOrDefault(start, end *time.Time) (pgtype.Timestamptz, pgtype.Timestamptz) {
	if start != nil && end != nil {
		return toPgTime(start), toPgTime(end)
	}
	now := time.Now().UTC()
	e := now.AddDate(0, 1, 0)
	return pgtype.Timestamptz{Time: now, Valid: true}, pgtype.Timestamptz{Time: e, Valid: true}
}

// EnforceDocumentQuota is the send-time guard. Returns ErrQuotaExceeded
// when the org has hit document_quota_monthly for the current period.
// Unlimited plans (quota=0) always pass. Orgs without a subscription
// row default to the 'free' plan's quota; if 'free' is missing too the
// guard fails open (don't lock new orgs out before they pick a plan).
func (e *Engine) EnforceDocumentQuota(ctx context.Context, orgID uuid.UUID) error {
	plan, sub, err := e.PlanForOrg(ctx, orgID)
	if err != nil || plan == nil {
		return nil
	}
	if plan.DocumentQuotaMonthly == 0 {
		return nil
	}
	start, end := quotaPeriod(sub, time.Now().UTC())
	count, err := e.Queries.CountDocumentsInPeriodForOrg(ctx, generated.CountDocumentsInPeriodForOrgParams{
		OrgID:       orgID,
		CreatedAt:   pgtype.Timestamptz{Time: start, Valid: true},
		CreatedAt_2: pgtype.Timestamptz{Time: end, Valid: true},
	})
	if err != nil {
		return nil
	}
	if int32(count) >= plan.DocumentQuotaMonthly {
		return fmt.Errorf("%w: plan %q allows %d documents per period; org has used %d", ErrQuotaExceeded, plan.Slug, plan.DocumentQuotaMonthly, count)
	}
	return nil
}

// PlanForOrg is the single entitlement gate. It returns the org's PAID plan
// only when the subscription is confirmed-entitled (see isEntitled); for a
// never-checked-out org, an abandoned/incomplete checkout, a payment failure,
// or a lapsed period it returns the free plan. The (possibly non-entitled)
// subscription row is returned too so callers can reason about the period.
// Centralising the active/period check here means every reader
// (EnforceDocumentQuota, HasFeature, the billing handlers) inherits correct
// fail-closed behaviour without scattering status checks.
func (e *Engine) PlanForOrg(ctx context.Context, orgID uuid.UUID) (*generated.BillingPlan, *generated.OrgSubscription, error) {
	sub, err := e.Queries.GetOrgSubscription(ctx, orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		free, ferr := e.Queries.GetBillingPlanBySlug(ctx, "free")
		if ferr != nil {
			return nil, nil, nil
		}
		return free, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if !isEntitled(sub, time.Now().UTC()) {
		free, ferr := e.Queries.GetBillingPlanBySlug(ctx, "free")
		if ferr != nil {
			return nil, sub, nil
		}
		return free, sub, nil
	}
	plan, err := e.Queries.GetBillingPlanByID(ctx, sub.PlanID)
	if err != nil {
		return nil, sub, err
	}
	return plan, sub, nil
}

// HasFeature reports whether the org's entitled plan grants a features_json
// capability (qes/aes/branding/evidence/mcp/white_label/sso). Because
// PlanForOrg returns the free plan for any non-entitled subscription, an
// unpaid/lapsed org fails closed automatically.
func (e *Engine) HasFeature(ctx context.Context, orgID uuid.UUID, key string) (bool, error) {
	plan, _, err := e.PlanForOrg(ctx, orgID)
	if err != nil {
		return false, err
	}
	// A nil plan despite a wired billing engine means the free row could not be read
	// (a seeded, migrated instance always resolves at least the free plan). That is a
	// misconfiguration, not a reason to ungate: fail CLOSED so a missing/renamed free
	// row cannot silently unlock paid features for every org. Dev/e2e/tests that run
	// without billing leave the handler's Billing engine nil and never reach here.
	if plan == nil {
		return false, nil
	}
	var m map[string]any
	if uerr := json.Unmarshal(plan.FeaturesJson, &m); uerr != nil {
		return false, nil
	}
	b, _ := m[key].(bool)
	return b, nil
}

// isEntitled reports whether a subscription currently grants its paid plan.
// Entitlement requires an active/trialing/cancelled status AND being within
// the paid period (current_period_end in the future). A missing period means
// no confirmed window, so it fails closed; cancel-at-period-end keeps access
// until the period lapses.
func isEntitled(sub *generated.OrgSubscription, now time.Time) bool {
	if sub == nil {
		return false
	}
	switch sub.Status {
	case "active", "trialing", "cancelled":
	default:
		return false
	}
	return sub.CurrentPeriodEnd.Valid && sub.CurrentPeriodEnd.Time.After(now)
}

// quotaPeriod returns the document-count window: the entitled subscription's
// paid period, else a rolling 30 days for free/no-sub orgs. Single source of
// truth so the send-time guard and the warning sweep agree.
func quotaPeriod(sub *generated.OrgSubscription, now time.Time) (time.Time, time.Time) {
	if isEntitled(sub, now) && sub.CurrentPeriodStart.Valid && sub.CurrentPeriodEnd.Valid {
		return sub.CurrentPeriodStart.Time, sub.CurrentPeriodEnd.Time
	}
	return now.AddDate(0, 0, -30), now
}

func toPgTime(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

func statusFromEventKind(kind string) string {
	switch kind {
	case "invoice.paid":
		return "paid"
	case "invoice.failed":
		return "failed"
	}
	return "open"
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func ifPaid(kind string, now time.Time) pgtype.Timestamptz {
	if kind == "invoice.paid" {
		return pgtype.Timestamptz{Time: now, Valid: true}
	}
	return pgtype.Timestamptz{}
}
