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

type Engine struct {
	Queries    *generated.Queries
	Provider   Provider
	PublicURL  string
	WebhookURL string
}

func New(q *generated.Queries, provider Provider, publicURL, webhookURL string) *Engine {
	if provider == nil {
		provider = MockProvider{}
	}
	return &Engine{Queries: q, Provider: provider, PublicURL: publicURL, WebhookURL: webhookURL}
}

func (e *Engine) ListPlans(ctx context.Context) ([]*generated.BillingPlan, error) {
	return e.Queries.ListActiveBillingPlans(ctx)
}

func (e *Engine) GetSubscription(ctx context.Context, orgID uuid.UUID) (*generated.OrgSubscription, error) {
	row, err := e.Queries.GetOrgSubscription(ctx, orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSubscriptionNone
	}
	return row, err
}

type StartCheckoutInput struct {
	OrgID     uuid.UUID
	OrgEmail  string
	OrgName   string
	PlanSlug  string
	Interval  string
	ReturnURL string
}

// PreparedCheckout contains a durable intent, not provider-created state. The
// caller first commits Params with its audit entry; CompletePreparedCheckout
// performs the network calls afterwards and can safely be retried.
type PreparedCheckout struct {
	ActivationKey uuid.UUID
	Params        generated.InsertBillingCheckoutIntentParams
	ProviderInput CheckoutInput
}

func (e *Engine) PrepareCheckout(ctx context.Context, in StartCheckoutInput) (PreparedCheckout, error) {
	if e == nil || e.Provider == nil || e.Queries == nil {
		return PreparedCheckout{}, ErrDisabled
	}
	if in.OrgID == uuid.Nil || in.PlanSlug == "" || !validInterval(in.Interval) {
		return PreparedCheckout{}, ErrInvalidCheckout
	}
	plan, err := e.Queries.GetBillingPlanBySlug(ctx, in.PlanSlug)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !plan.Active) {
		return PreparedCheckout{}, ErrPlanNotFound
	}
	if err != nil {
		return PreparedCheckout{}, err
	}
	price := plan.MonthlyPriceCents
	if in.Interval == "yearly" {
		price = plan.YearlyPriceCents
	}
	if price <= 0 || !validCurrency(plan.Currency) {
		return PreparedCheckout{}, fmt.Errorf("%w: selected plan has no payable price", ErrInvalidCheckout)
	}

	key := uuid.New()
	existingCustomerID := ""
	open, err := e.Queries.GetOpenBillingCheckoutForOrg(ctx, in.OrgID)
	switch {
	case err == nil:
		if open.PlanID != plan.ID || open.Provider != e.Provider.Name() || open.Interval != in.Interval ||
			open.AmountCents != price || open.Currency != plan.Currency {
			return PreparedCheckout{}, ErrCheckoutInProgress
		}
		key = open.ActivationKey
		if open.ProviderCustomerID.Valid {
			existingCustomerID = open.ProviderCustomerID.String
		}
	case errors.Is(err, pgx.ErrNoRows):
		// Reuse a customer created by a prior terminal checkout so a canceled
		// or expired first payment does not create duplicate Mollie customers.
		latest, latestErr := e.Queries.GetLatestBillingCheckoutForOrg(ctx, in.OrgID)
		if latestErr == nil && latest.Provider == e.Provider.Name() && latest.ProviderCustomerID.Valid {
			existingCustomerID = latest.ProviderCustomerID.String
		} else if latestErr != nil && !errors.Is(latestErr, pgx.ErrNoRows) {
			return PreparedCheckout{}, latestErr
		}
	case err != nil:
		return PreparedCheckout{}, err
	}
	sub, subErr := e.Queries.GetOrgSubscription(ctx, in.OrgID)
	if subErr == nil {
		// Starting a second recurring subscription while the first can still
		// renew would double-charge the org. A replacement checkout is only
		// allowed after a provider cancellation was persisted and its paid
		// period ended.
		if sub.ProviderSubscriptionID.Valid && (!sub.CancelAtPeriodEnd || isEntitled(sub, time.Now().UTC())) {
			return PreparedCheckout{}, ErrCheckoutInProgress
		}
		if existingCustomerID == "" && sub.Provider == e.Provider.Name() && sub.ProviderCustomerID.Valid {
			existingCustomerID = sub.ProviderCustomerID.String
		}
	} else if !errors.Is(subErr, pgx.ErrNoRows) {
		return PreparedCheckout{}, subErr
	}
	params := generated.InsertBillingCheckoutIntentParams{
		ActivationKey: key, OrgID: in.OrgID, PlanID: plan.ID, Provider: e.Provider.Name(),
		Interval: in.Interval, AmountCents: price, Currency: plan.Currency,
	}
	return PreparedCheckout{
		ActivationKey: key,
		Params:        params,
		ProviderInput: CheckoutInput{
			ActivationKey: key, OrgID: in.OrgID, OrgEmail: in.OrgEmail, OrgName: in.OrgName,
			PlanSlug: plan.Slug, PriceCents: int(price), Currency: plan.Currency, Interval: in.Interval,
			ReturnURL: in.ReturnURL, WebhookURL: e.WebhookURL, Description: "Hash " + plan.Name,
			ExistingCustomerID: existingCustomerID,
		},
	}, nil
}

func PersistPreparedCheckout(ctx context.Context, q *generated.Queries, prepared PreparedCheckout) error {
	if q == nil || prepared.ActivationKey == uuid.Nil || prepared.Params.ActivationKey != prepared.ActivationKey {
		return errors.New("billing: invalid prepared checkout")
	}
	row, err := q.InsertBillingCheckoutIntent(ctx, prepared.Params)
	if err != nil {
		return err
	}
	if row == nil || row.ActivationKey != prepared.ActivationKey {
		return errors.New("billing: checkout intent persistence returned invalid state")
	}
	return nil
}

// CompletePreparedCheckout is retry-safe across a process crash. The state is
// moved to creating_payment before POST; a retry then asks the provider to
// reconcile by activation metadata before issuing another POST.
func (e *Engine) CompletePreparedCheckout(ctx context.Context, prepared PreparedCheckout) (string, error) {
	checkout, err := e.Queries.GetBillingCheckoutByKey(ctx, prepared.ActivationKey)
	if err != nil {
		return "", err
	}
	if !checkoutMatchesPrepared(checkout, prepared) {
		return "", ErrWebhookCorrelation
	}
	if checkout.State == "payment_pending" && checkout.CheckoutUrl.Valid && checkout.ProviderPaymentID.Valid {
		return checkout.CheckoutUrl.String, nil
	}
	if checkout.State == "active" {
		return prepared.ProviderInput.ReturnURL, nil
	}
	if checkout.State == "payment_paid" || checkout.State == "subscription_pending" {
		if !checkout.ProviderMandateID.Valid || !checkout.PaidAt.Valid {
			return "", errors.New("billing: paid checkout is missing its durable mandate checkpoint")
		}
		plan, planErr := e.Queries.GetBillingPlanByID(ctx, checkout.PlanID)
		if planErr != nil {
			return "", planErr
		}
		if err := e.activatePaidCheckout(ctx, checkout, plan, "", ""); err != nil {
			return "", err
		}
		return prepared.ProviderInput.ReturnURL, nil
	}
	if checkout.State != "intent" && checkout.State != "creating_payment" && checkout.State != "payment_pending" {
		return "", ErrInvalidCheckout
	}
	reconcile := checkout.State == "creating_payment" || checkout.State == "payment_pending"
	if checkout.State != "payment_pending" {
		checkout, err = e.Queries.MarkBillingCheckoutCreatingPayment(ctx, prepared.ActivationKey)
		if err != nil {
			return "", err
		}
	}
	providerInput := prepared.ProviderInput
	providerInput.Reconcile = reconcile
	if checkout.ProviderCustomerID.Valid {
		providerInput.ExistingCustomerID = checkout.ProviderCustomerID.String
	}
	result, err := e.Provider.CreateCheckout(ctx, providerInput)
	if err != nil {
		if errors.Is(err, ErrCheckoutPaymentTerminal) {
			_, _ = e.Queries.MarkBillingCheckoutFailed(ctx, prepared.ActivationKey)
			return "", ErrInvalidCheckout
		}
		return "", err
	}
	if result == nil || result.ProviderCustomerID == "" || result.ProviderPaymentID == "" || result.CheckoutURL == "" {
		return "", errors.New("billing: provider returned incomplete checkout state")
	}
	checkout, err = e.Queries.SetBillingCheckoutPayment(ctx, generated.SetBillingCheckoutPaymentParams{
		ActivationKey:      prepared.ActivationKey,
		ProviderCustomerID: text(result.ProviderCustomerID), ProviderPaymentID: text(result.ProviderPaymentID),
		CheckoutUrl: text(result.CheckoutURL),
	})
	if err != nil {
		return "", err
	}
	if checkout == nil || !checkout.ProviderPaymentID.Valid || checkout.ProviderPaymentID.String != result.ProviderPaymentID {
		return "", errors.New("billing: persisted checkout payment does not match provider response")
	}
	return checkout.CheckoutUrl.String, nil
}

func checkoutMatchesPrepared(row *generated.BillingCheckoutActivation, prepared PreparedCheckout) bool {
	return row != nil && row.ActivationKey == prepared.ActivationKey && row.OrgID == prepared.Params.OrgID &&
		row.PlanID == prepared.Params.PlanID && row.Provider == prepared.Params.Provider &&
		row.Interval == prepared.Params.Interval && row.AmountCents == prepared.Params.AmountCents &&
		row.Currency == prepared.Params.Currency
}

func (e *Engine) StartCheckout(ctx context.Context, in StartCheckoutInput) (string, error) {
	prepared, err := e.PrepareCheckout(ctx, in)
	if err != nil {
		return "", err
	}
	if err := PersistPreparedCheckout(ctx, e.Queries, prepared); err != nil {
		return "", fmt.Errorf("billing: persist checkout intent: %w", err)
	}
	return e.CompletePreparedCheckout(ctx, prepared)
}

func (e *Engine) PrepareCancellation(ctx context.Context, orgID uuid.UUID) (generated.SetSubscriptionCancelAtPeriodEndParams, error) {
	sub, err := e.Queries.GetOrgSubscription(ctx, orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return generated.SetSubscriptionCancelAtPeriodEndParams{}, ErrSubscriptionNone
	}
	if err != nil {
		return generated.SetSubscriptionCancelAtPeriodEndParams{}, err
	}
	if sub.ProviderSubscriptionID.Valid {
		if !sub.ProviderCustomerID.Valid {
			return generated.SetSubscriptionCancelAtPeriodEndParams{}, errors.New("billing: subscription has no provider customer id")
		}
		if err := e.Provider.CancelSubscription(ctx, sub.ProviderCustomerID.String, sub.ProviderSubscriptionID.String); err != nil {
			return generated.SetSubscriptionCancelAtPeriodEndParams{}, err
		}
	}
	return generated.SetSubscriptionCancelAtPeriodEndParams{OrgID: orgID, CancelAtPeriodEnd: true}, nil
}

func (e *Engine) CancelAtPeriodEnd(ctx context.Context, orgID uuid.UUID) error {
	params, err := e.PrepareCancellation(ctx, orgID)
	if err != nil {
		return err
	}
	_, err = e.Queries.SetSubscriptionCancelAtPeriodEnd(ctx, params)
	return err
}

func (e *Engine) HandleWebhook(ctx context.Context, raw []byte, headers map[string]string) error {
	// Mollie's classic webhook gives the receiver 15 seconds. Bound the full
	// dereference/reconcile/commit sequence below that so a transient provider
	// delay produces a retryable response instead of an ambiguous late 2xx.
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	event, err := e.Provider.ParseWebhook(ctx, raw, headers)
	if err != nil {
		return err
	}
	if event == nil {
		return ErrInvalidWebhook
	}
	if event.SequenceType == "recurring" {
		return e.handleRecurringPayment(ctx, event)
	}
	if event.SequenceType != "first" {
		return fmt.Errorf("%w: unsupported sequence type", ErrWebhookCorrelation)
	}
	checkout, err := e.Queries.GetBillingCheckoutByPayment(ctx, generated.GetBillingCheckoutByPaymentParams{
		Provider: e.Provider.Name(), ProviderPaymentID: text(event.ProviderPaymentID),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// The POST may have committed at Mollie just before this process died
		// saving its response. Bind only an intent named by authenticated,
		// dereferenced payment metadata; from this checkpoint all later retries
		// find the payment by its provider ID.
		checkout, err = e.Queries.GetBillingCheckoutByKey(ctx, event.ActivationKey)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrWebhookCorrelation
		}
		if err != nil {
			return err
		}
		if checkout.State != "creating_payment" && checkout.State != "payment_pending" {
			return ErrWebhookCorrelation
		}
		plan, planErr := e.Queries.GetBillingPlanByID(ctx, checkout.PlanID)
		if planErr != nil {
			return planErr
		}
		if err := correlateUnboundPayment(checkout, plan, event, e.Provider.Name()); err != nil {
			return err
		}
		checkout, err = e.Queries.BindBillingCheckoutPaymentFromWebhook(ctx, generated.BindBillingCheckoutPaymentFromWebhookParams{
			ActivationKey: checkout.ActivationKey, ProviderCustomerID: text(event.ProviderCustomerID),
			ProviderPaymentID: text(event.ProviderPaymentID),
		})
		if err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	plan, err := e.Queries.GetBillingPlanByID(ctx, checkout.PlanID)
	if err != nil {
		return err
	}
	if err := correlatePayment(checkout, plan, event, false, e.Provider.Name()); err != nil {
		return err
	}
	if checkout.State == "failed" || (checkout.State == "active" && event.Kind != "invoice.paid") {
		return ErrWebhookCorrelation
	}

	if event.Kind != "invoice.paid" {
		if err := e.persistUnactivatedInvoice(ctx, checkout, plan, event); err != nil {
			return err
		}
		if event.Kind == "invoice.failed" {
			_, err = e.Queries.MarkBillingCheckoutFailed(ctx, checkout.ActivationKey)
		}
		return err
	}
	if event.PaidAt == nil || event.MandateID == "" {
		return fmt.Errorf("%w: paid first payment lacks mandate evidence", ErrWebhookCorrelation)
	}
	checkout, err = e.Queries.MarkBillingCheckoutPaymentPaid(ctx, generated.MarkBillingCheckoutPaymentPaidParams{
		Provider: e.Provider.Name(), ProviderPaymentID: text(event.ProviderPaymentID),
		ProviderCustomerID: text(event.ProviderCustomerID), PaidAt: pgTime(*event.PaidAt),
		ProviderMandateID: text(event.MandateID),
	})
	if err != nil {
		return err
	}
	if checkout.State == "active" && checkout.ProviderSubscriptionID.Valid {
		return nil
	}
	return e.activatePaidCheckout(ctx, checkout, plan, event.HostedInvoiceURL, event.PDFURL)
}

func (e *Engine) activatePaidCheckout(ctx context.Context, checkout *generated.BillingCheckoutActivation, plan *generated.BillingPlan, hostedInvoiceURL, pdfURL string) error {
	if checkout == nil || plan == nil || !checkout.ProviderCustomerID.Valid || !checkout.ProviderPaymentID.Valid ||
		!checkout.ProviderMandateID.Valid || !checkout.PaidAt.Valid {
		return errors.New("billing: paid checkout checkpoint is incomplete")
	}
	checkout, err := e.Queries.MarkBillingCheckoutSubscriptionPending(ctx, checkout.ActivationKey)
	if err != nil {
		return err
	}
	result, err := e.Provider.CreateSubscription(ctx, SubscriptionInput{
		ActivationKey: checkout.ActivationKey, OrgID: checkout.OrgID, PlanSlug: plan.Slug,
		ProviderCustomerID: checkout.ProviderCustomerID.String, MandateID: checkout.ProviderMandateID.String,
		PriceCents: int(checkout.AmountCents), Currency: checkout.Currency, Interval: checkout.Interval,
		WebhookURL: e.WebhookURL, Description: "Hash " + plan.Name,
	})
	if err != nil {
		return err
	}
	if result == nil || result.ProviderSubscriptionID == "" {
		return errors.New("billing: provider returned no recurring subscription")
	}
	periodStart, periodEnd := paidPeriod(checkout.PaidAt.Time, checkout.Interval)
	activated, err := e.Queries.ActivateBillingCheckout(ctx, generated.ActivateBillingCheckoutParams{
		InputSubscriptionID: text(result.ProviderSubscriptionID), ActivationKey: checkout.ActivationKey,
		InputCustomerID: checkout.ProviderCustomerID, InputPaymentID: checkout.ProviderPaymentID,
		PeriodStart: pgTime(periodStart), PeriodEnd: pgTime(periodEnd), Description: "Hash " + plan.Name,
		HostedInvoiceUrl: optionalText(hostedInvoiceURL), PdfUrl: optionalText(pdfURL),
	})
	if err != nil {
		return err
	}
	if activated == nil || activated.Status != "active" || !activated.ProviderSubscriptionID.Valid ||
		activated.ProviderSubscriptionID.String != result.ProviderSubscriptionID {
		return errors.New("billing: activation transaction returned invalid subscription state")
	}
	return nil
}

func (e *Engine) handleRecurringPayment(ctx context.Context, event *WebhookEvent) error {
	checkout, err := e.Queries.GetBillingCheckoutBySubscription(ctx, generated.GetBillingCheckoutBySubscriptionParams{
		Provider: e.Provider.Name(), ProviderSubscriptionID: text(event.ProviderSubscriptionID),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrWebhookCorrelation
	}
	if err != nil {
		return err
	}
	plan, err := e.Queries.GetBillingPlanByID(ctx, checkout.PlanID)
	if err != nil {
		return err
	}
	if err := correlatePayment(checkout, plan, event, true, e.Provider.Name()); err != nil {
		return err
	}
	sub, err := e.Queries.GetOrgSubscription(ctx, checkout.OrgID)
	if err != nil || sub.ProviderSubscriptionID.String != event.ProviderSubscriptionID || !sub.ProviderSubscriptionID.Valid {
		if err != nil {
			return err
		}
		return ErrWebhookCorrelation
	}
	if event.Kind == "invoice.paid" {
		if event.PaidAt == nil {
			return ErrWebhookCorrelation
		}
		start, end := paidPeriod(*event.PaidAt, checkout.Interval)
		_, err = e.Queries.ApplyRecurringBillingPayment(ctx, generated.ApplyRecurringBillingPaymentParams{
			ActivationKey: checkout.ActivationKey, InputCustomerID: text(event.ProviderCustomerID),
			InputSubscriptionID: text(event.ProviderSubscriptionID), PeriodStart: pgTime(start), PeriodEnd: pgTime(end),
			ProviderPaymentID: event.ProviderPaymentID, Description: "Hash " + plan.Name,
			HostedInvoiceUrl: optionalText(event.HostedInvoiceURL), PdfUrl: optionalText(event.PDFURL),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrWebhookCorrelation
		}
		return err
	}
	if event.ProviderCreatedAt == nil || (sub.CurrentPeriodStart.Valid && event.ProviderCreatedAt.Before(sub.CurrentPeriodStart.Time)) {
		return ErrWebhookCorrelation
	}
	if err := e.insertInvoice(ctx, checkout, sub, plan, event); err != nil {
		return err
	}
	if event.Kind == "invoice.failed" {
		_, err = e.Queries.UpsertOrgSubscription(ctx, generated.UpsertOrgSubscriptionParams{
			OrgID: sub.OrgID, PlanID: sub.PlanID, Provider: sub.Provider,
			ProviderCustomerID: sub.ProviderCustomerID, ProviderSubscriptionID: sub.ProviderSubscriptionID,
			Status: "past_due", CurrentPeriodStart: sub.CurrentPeriodStart, CurrentPeriodEnd: sub.CurrentPeriodEnd,
			CancelAtPeriodEnd: sub.CancelAtPeriodEnd, TrialEndsAt: sub.TrialEndsAt,
		})
	}
	return err
}

func correlatePayment(checkout *generated.BillingCheckoutActivation, plan *generated.BillingPlan, event *WebhookEvent, recurring bool, expectedProvider string) error {
	if err := correlateUnboundPayment(checkout, plan, event, expectedProvider); err != nil {
		return err
	}
	if checkout.ProviderCustomerID.String != event.ProviderCustomerID || !checkout.ProviderCustomerID.Valid {
		return ErrWebhookCorrelation
	}
	if recurring {
		if checkout.State != "active" || !checkout.ProviderSubscriptionID.Valid ||
			checkout.ProviderSubscriptionID.String != event.ProviderSubscriptionID {
			return ErrWebhookCorrelation
		}
	} else {
		if !checkout.ProviderPaymentID.Valid || checkout.ProviderPaymentID.String != event.ProviderPaymentID ||
			event.ProviderSubscriptionID != "" {
			return ErrWebhookCorrelation
		}
	}
	return nil
}

func correlateUnboundPayment(checkout *generated.BillingCheckoutActivation, plan *generated.BillingPlan, event *WebhookEvent, expectedProvider string) error {
	if checkout == nil || plan == nil || event == nil || checkout.ActivationKey != event.ActivationKey ||
		checkout.OrgID != event.OrgID || checkout.Provider != expectedProvider ||
		checkout.AmountCents != int32(event.AmountCents) || checkout.Currency != event.Currency ||
		checkout.Interval != event.Interval || plan.Slug != event.PlanSlug ||
		(checkout.State != "creating_payment" && checkout.State != "payment_pending" && checkout.State != "payment_paid" &&
			checkout.State != "subscription_pending" && checkout.State != "active" && checkout.State != "failed") {
		return ErrWebhookCorrelation
	}
	return nil
}

func (e *Engine) persistUnactivatedInvoice(ctx context.Context, checkout *generated.BillingCheckoutActivation, plan *generated.BillingPlan, event *WebhookEvent) error {
	return e.insertInvoice(ctx, checkout, nil, plan, event)
}

func (e *Engine) insertInvoice(ctx context.Context, checkout *generated.BillingCheckoutActivation, sub *generated.OrgSubscription, plan *generated.BillingPlan, event *WebhookEvent) error {
	subscriptionID := pgtype.UUID{}
	if sub != nil {
		subscriptionID = pgtype.UUID{Bytes: sub.ID, Valid: true}
	}
	paidAt := pgtype.Timestamptz{}
	if event.PaidAt != nil {
		paidAt = pgTime(*event.PaidAt)
	}
	_, err := e.Queries.InsertBillingInvoice(ctx, generated.InsertBillingInvoiceParams{
		OrgID: checkout.OrgID, SubscriptionID: subscriptionID, Provider: checkout.Provider,
		ProviderPaymentID: event.ProviderPaymentID, Status: statusFromEventKind(event.Kind),
		AmountCents: int32(event.AmountCents), Currency: event.Currency, Description: "Hash " + plan.Name,
		PaidAt: paidAt, HostedInvoiceUrl: optionalText(event.HostedInvoiceURL), PdfUrl: optionalText(event.PDFURL),
	})
	return err
}

func paidPeriod(start time.Time, interval string) (time.Time, time.Time) {
	start = start.UTC()
	if interval == "yearly" {
		return start, start.AddDate(1, 0, 0)
	}
	return start, start.AddDate(0, 1, 0)
}

// EnforceDocumentQuota enforces both plan dimensions. Any inability to read a
// plan or usage is a typed, retryable availability error rather than a bypass.
func (e *Engine) EnforceDocumentQuota(ctx context.Context, orgID uuid.UUID) error {
	if e == nil || e.Queries == nil {
		return &EntitlementUnavailableError{Stage: "quota engine unavailable"}
	}
	plan, sub, err := e.PlanForOrg(ctx, orgID)
	if err != nil {
		if errors.Is(err, ErrEntitlementUnavailable) {
			return err
		}
		return &EntitlementUnavailableError{Stage: "load plan", Err: err}
	}
	if plan == nil {
		return &EntitlementUnavailableError{Stage: "plan missing"}
	}
	if plan.DocumentQuotaMonthly == 0 && plan.RecipientQuotaMonthly == 0 {
		return nil
	}
	start, end := quotaPeriod(sub, time.Now().UTC())
	usage, err := e.Queries.CountBillingUsageInPeriodForOrg(ctx, generated.CountBillingUsageInPeriodForOrgParams{
		OrgID: orgID, PeriodStart: pgTime(start), PeriodEnd: pgTime(end),
	})
	if err != nil {
		return &EntitlementUnavailableError{Stage: "load usage", Err: err}
	}
	if usage == nil {
		return &EntitlementUnavailableError{Stage: "usage missing"}
	}
	if plan.DocumentQuotaMonthly > 0 && usage.DocumentsUsed > int64(plan.DocumentQuotaMonthly) {
		return fmt.Errorf("%w: plan %q allows %d documents per period; org has used %d", ErrQuotaExceeded, plan.Slug, plan.DocumentQuotaMonthly, usage.DocumentsUsed)
	}
	if plan.RecipientQuotaMonthly > 0 && usage.RecipientsUsed > int64(plan.RecipientQuotaMonthly) {
		return fmt.Errorf("%w: plan %q allows %d recipients per period; org has used %d", ErrQuotaExceeded, plan.Slug, plan.RecipientQuotaMonthly, usage.RecipientsUsed)
	}
	return nil
}

// LockDocumentQuotaMutation serializes every quota-consuming authoring
// transaction for an organization. Callers must use the transaction-bound q,
// take this lock before inserting a document or recipient, and keep the
// transaction open through EnforceDocumentQuotaMutation and commit.
//
// A nil Engine means billing is intentionally disabled for this instance, which
// matches the existing send and feature-gate behavior. Once billing is wired,
// missing transaction dependencies fail closed as an entitlement outage.
func (e *Engine) LockDocumentQuotaMutation(ctx context.Context, q *generated.Queries, orgID uuid.UUID) error {
	if e == nil {
		return nil
	}
	if q == nil || orgID == uuid.Nil {
		return &EntitlementUnavailableError{Stage: "lock quota mutation dependencies"}
	}
	if err := q.LockBillingUsageForOrg(ctx, orgID.String()); err != nil {
		return &EntitlementUnavailableError{Stage: "lock quota mutation", Err: err}
	}
	return nil
}

// EnforceDocumentQuotaMutation counts from the same transaction that inserted
// the prospective document or recipient. Quotas therefore reject only when the
// new row would put usage over the published limit, and rollback removes both
// the row and its audit event.
func (e *Engine) EnforceDocumentQuotaMutation(ctx context.Context, q *generated.Queries, orgID uuid.UUID) error {
	if e == nil {
		return nil
	}
	if q == nil || orgID == uuid.Nil {
		return &EntitlementUnavailableError{Stage: "enforce quota mutation dependencies"}
	}
	transactional := *e
	transactional.Queries = q
	return transactional.EnforceDocumentQuota(ctx, orgID)
}

func (e *Engine) PlanForOrg(ctx context.Context, orgID uuid.UUID) (*generated.BillingPlan, *generated.OrgSubscription, error) {
	sub, err := e.Queries.GetOrgSubscription(ctx, orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		free, freeErr := e.Queries.GetBillingPlanBySlug(ctx, "free")
		if freeErr != nil {
			return nil, nil, &EntitlementUnavailableError{Stage: "load free plan", Err: freeErr}
		}
		if free == nil {
			return nil, nil, &EntitlementUnavailableError{Stage: "free plan missing"}
		}
		return free, nil, nil
	}
	if err != nil {
		return nil, nil, &EntitlementUnavailableError{Stage: "load subscription", Err: err}
	}
	if !isEntitled(sub, time.Now().UTC()) {
		free, freeErr := e.Queries.GetBillingPlanBySlug(ctx, "free")
		if freeErr != nil {
			return nil, sub, &EntitlementUnavailableError{Stage: "load free plan", Err: freeErr}
		}
		if free == nil {
			return nil, sub, &EntitlementUnavailableError{Stage: "free plan missing"}
		}
		return free, sub, nil
	}
	plan, err := e.Queries.GetBillingPlanByID(ctx, sub.PlanID)
	if err != nil {
		return nil, sub, &EntitlementUnavailableError{Stage: "load entitled plan", Err: err}
	}
	if plan == nil {
		return nil, sub, &EntitlementUnavailableError{Stage: "entitled plan missing"}
	}
	return plan, sub, nil
}

func (e *Engine) HasFeature(ctx context.Context, orgID uuid.UUID, key string) (bool, error) {
	plan, _, err := e.PlanForOrg(ctx, orgID)
	if err != nil {
		return false, err
	}
	if plan == nil {
		return false, &EntitlementUnavailableError{Stage: "plan missing"}
	}
	var features map[string]any
	if err := json.Unmarshal(plan.FeaturesJson, &features); err != nil {
		return false, &EntitlementUnavailableError{Stage: "invalid plan features", Err: err}
	}
	value, _ := features[key].(bool)
	return value, nil
}

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

func quotaPeriod(sub *generated.OrgSubscription, now time.Time) (time.Time, time.Time) {
	if isEntitled(sub, now) && sub.CurrentPeriodStart.Valid && sub.CurrentPeriodEnd.Valid {
		return sub.CurrentPeriodStart.Time, sub.CurrentPeriodEnd.Time
	}
	return now.AddDate(0, 0, -30), now
}

func statusFromEventKind(kind string) string {
	if kind == "invoice.paid" {
		return "paid"
	}
	if kind == "invoice.failed" {
		return "failed"
	}
	return "open"
}

func text(value string) pgtype.Text         { return pgtype.Text{String: value, Valid: value != ""} }
func optionalText(value string) pgtype.Text { return text(value) }
func pgTime(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value.UTC(), Valid: true}
}
