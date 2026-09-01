// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// requireFeature gates a handler on a billing feature flag
// (qes/aes/branding/evidence_bundle/...). Returns true when the org is entitled;
// otherwise writes 402/503 and returns false. A nil Billing engine means billing is
// not wired at all (dev/e2e/tests) and is the only ungate. When billing IS wired, a
// read error fails CLOSED (deny): a transient DB blip or a renamed plan row must not
// silently unlock paid features (qes/branding/evidence) for every org with no signal.
func (s *Server) requireFeature(w http.ResponseWriter, r *http.Request, orgID uuid.UUID, key string) bool {
	if s.Billing == nil {
		return true
	}
	ok, err := s.Billing.HasFeature(r.Context(), orgID, key)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "entitlement check temporarily unavailable")
		return false
	}
	if !ok {
		writeJSON(w, http.StatusPaymentRequired, map[string]any{
			"error":       "your plan does not include the '" + key + "' feature",
			"feature":     key,
			"upgrade_url": "/settings/billing",
		})
		return false
	}
	return true
}

// writeAuthoringQuotaError maps the typed errors produced by an atomic
// document/recipient quota mutation. It returns false for unrelated failures so
// the caller can use its normal internal-error path without exposing details.
func (s *Server) writeAuthoringQuotaError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, billing.ErrQuotaExceeded):
		writeJSON(w, http.StatusPaymentRequired, map[string]any{
			"error":       err.Error(),
			"upgrade_url": "/settings/billing",
		})
		return true
	case errors.Is(err, billing.ErrEntitlementUnavailable):
		writeError(w, http.StatusServiceUnavailable, "billing entitlement check temporarily unavailable")
		return true
	default:
		return false
	}
}

func pgTimeOrNil(t pgtype.Timestamptz) any {
	if !t.Valid {
		return nil
	}
	return t.Time.UTC()
}

// handleListBillingPlans returns the active plan catalog. Session-authed
// because plan slugs + prices are not secret but the org settings UI is
// the only consumer that should see them inline.
func (s *Server) handleListBillingPlans(w http.ResponseWriter, r *http.Request) {
	if s.Billing == nil {
		writeJSON(w, http.StatusOK, map[string]any{"plans": []any{}, "billing_enabled": false})
		return
	}
	plans, err := s.Billing.ListPlans(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(plans))
	for _, p := range plans {
		out = append(out, map[string]any{
			"id":                      p.ID.String(),
			"slug":                    p.Slug,
			"name":                    p.Name,
			"description":             p.Description,
			"monthly_price_cents":     p.MonthlyPriceCents,
			"yearly_price_cents":      p.YearlyPriceCents,
			"currency":                p.Currency,
			"document_quota_monthly":  p.DocumentQuotaMonthly,
			"recipient_quota_monthly": p.RecipientQuotaMonthly,
			"features":                p.FeaturesJson,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"plans": out, "billing_enabled": true, "provider": s.Billing.Provider.Name()})
}

// handleGetBillingSubscription returns the org's current subscription
// + the plan it points at. Orgs without a subscription row get the
// free plan implied.
func (s *Server) handleGetBillingSubscription(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if s.Billing == nil {
		writeJSON(w, http.StatusOK, map[string]any{"plan": map[string]any{"slug": "free"}, "subscription": nil, "billing_enabled": false})
		return
	}
	plan, sub, err := s.Billing.PlanForOrg(r.Context(), u.OrgID)
	if err != nil {
		if errors.Is(err, billing.ErrEntitlementUnavailable) {
			writeError(w, http.StatusServiceUnavailable, "entitlement check temporarily unavailable")
			return
		}
		writeInternalError(w, err)
		return
	}
	planOut := map[string]any{}
	if plan != nil {
		planOut = map[string]any{
			"id":                      plan.ID.String(),
			"slug":                    plan.Slug,
			"name":                    plan.Name,
			"monthly_price_cents":     plan.MonthlyPriceCents,
			"yearly_price_cents":      plan.YearlyPriceCents,
			"currency":                plan.Currency,
			"document_quota_monthly":  plan.DocumentQuotaMonthly,
			"recipient_quota_monthly": plan.RecipientQuotaMonthly,
			"features":                plan.FeaturesJson,
		}
	}
	subOut := map[string]any{}
	if sub != nil {
		subOut = map[string]any{
			"id":                   sub.ID.String(),
			"status":               sub.Status,
			"provider":             sub.Provider,
			"current_period_start": pgTimeOrNil(sub.CurrentPeriodStart),
			"current_period_end":   pgTimeOrNil(sub.CurrentPeriodEnd),
			"cancel_at_period_end": sub.CancelAtPeriodEnd,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"plan":            planOut,
		"subscription":    subOut,
		"billing_enabled": true,
	})
}

type checkoutInput struct {
	PlanSlug string `json:"plan_slug"`
	Interval string `json:"interval"` // monthly | yearly
}

type billingOrgLoader interface {
	GetOrg(context.Context, uuid.UUID) (*generated.Org, error)
}

func billingCustomerOrgName(ctx context.Context, loader billingOrgLoader, orgID uuid.UUID) (string, error) {
	if loader == nil || orgID == uuid.Nil {
		return "", errors.New("billing customer organization unavailable")
	}
	org, err := loader.GetOrg(ctx, orgID)
	if err != nil {
		return "", err
	}
	if org == nil || org.ID != orgID || strings.TrimSpace(org.Name) == "" {
		return "", errors.New("billing customer organization unavailable")
	}
	return strings.TrimSpace(org.Name), nil
}

// handleStartBillingCheckout creates a checkout session with the
// provider + returns the hosted URL the user's browser navigates to.
func (s *Server) handleStartBillingCheckout(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if s.Billing == nil {
		writeError(w, http.StatusServiceUnavailable, "billing not enabled on this instance")
		return
	}
	var in checkoutInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Interval == "" {
		in.Interval = "monthly"
	}
	orgName, err := billingCustomerOrgName(r.Context(), s.Queries, u.OrgID)
	if err != nil {
		writeInternalErrorMsg(w, "load billing customer organization failed", err)
		return
	}
	returnURL := s.PublicURL + "/settings/billing?status=success"
	prepared, err := s.Billing.PrepareCheckout(r.Context(), billing.StartCheckoutInput{
		OrgID:     u.OrgID,
		OrgEmail:  u.Email,
		OrgName:   orgName,
		PlanSlug:  in.PlanSlug,
		Interval:  in.Interval,
		ReturnURL: returnURL,
	})
	if err != nil {
		if errors.Is(err, billing.ErrPlanNotFound) {
			writeError(w, http.StatusNotFound, "plan not found")
			return
		}
		if errors.Is(err, billing.ErrInvalidCheckout) {
			writeError(w, http.StatusBadRequest, "invalid checkout request")
			return
		}
		if errors.Is(err, billing.ErrCheckoutInProgress) {
			writeError(w, http.StatusConflict, "another checkout is already in progress")
			return
		}
		writeError(w, http.StatusBadGateway, "billing: "+err.Error())
		return
	}
	_, err = audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (uuid.UUID, error) {
			return prepared.ActivationKey, billing.PersistPreparedCheckout(r.Context(), q, prepared)
		},
		func(uuid.UUID) audit.Entry {
			return audit.Entry{
				OrgID:       u.OrgID,
				ActorUserID: &u.UserID,
				Kind:        audit.KindBillingCheckoutStarted,
				Payload:     map[string]any{"plan_slug": in.PlanSlug, "interval": in.Interval},
			}
		},
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, "billing: persist audited checkout: "+err.Error())
		return
	}
	url, err := s.Billing.CompletePreparedCheckout(r.Context(), prepared)
	if err != nil {
		if errors.Is(err, billing.ErrCheckoutInProgress) {
			writeError(w, http.StatusConflict, "checkout payment is already being activated")
			return
		}
		writeError(w, http.StatusBadGateway, "billing provider temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"checkout_url": url})
}

// handleCancelBillingSubscription marks the subscription cancel-at-
// period-end. The active period stays usable until expiry.
func (s *Server) handleCancelBillingSubscription(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if s.Billing == nil {
		writeError(w, http.StatusServiceUnavailable, "billing not enabled")
		return
	}
	params, err := s.Billing.PrepareCancellation(r.Context(), u.OrgID)
	if err != nil {
		if errors.Is(err, billing.ErrSubscriptionNone) {
			writeError(w, http.StatusNotFound, "no subscription to cancel")
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	_, err = audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (uuid.UUID, error) {
			_, err := q.SetSubscriptionCancelAtPeriodEnd(r.Context(), params)
			return u.OrgID, err
		},
		func(uuid.UUID) audit.Entry {
			return audit.Entry{
				OrgID:       u.OrgID,
				ActorUserID: &u.UserID,
				Kind:        audit.KindBillingSubscriptionCancelled,
				Payload:     map[string]any{"cancel_at_period_end": true},
			}
		},
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, "billing: persist audited cancellation: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleListBillingInvoices returns the most recent invoices for the
// session's org. Cap at 50 so the UI never paginates.
func (s *Server) handleListBillingInvoices(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if s.Billing == nil {
		writeJSON(w, http.StatusOK, map[string]any{"invoices": []any{}})
		return
	}
	rows, err := s.Queries.ListBillingInvoicesForOrg(r.Context(), generated.ListBillingInvoicesForOrgParams{OrgID: u.OrgID, Limit: 50})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, inv := range rows {
		out = append(out, map[string]any{
			"id":                 inv.ID.String(),
			"status":             inv.Status,
			"amount_cents":       inv.AmountCents,
			"currency":           inv.Currency,
			"description":        inv.Description,
			"hosted_invoice_url": inv.HostedInvoiceUrl.String,
			"pdf_url":            inv.PdfUrl.String,
			"paid_at":            pgTimeOrNil(inv.PaidAt),
			"created_at":         inv.CreatedAt.Time.UTC(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"invoices": out})
}

// handleBillingWebhook is the provider-facing webhook receiver. Public
// route gated by HMAC inside the engine. The path includes a per-
// instance secret so Mollie's standard URL-based authentication works.
//
// Mollie webhook payload: form-encoded "id=tr_xxx"; the provider
// dereferences the ID against api.mollie.com to verify authenticity.
// Mock provider accepts any JSON body for synthetic events.
func (s *Server) handleBillingWebhook(w http.ResponseWriter, r *http.Request) {
	if s.Billing == nil {
		writeError(w, http.StatusServiceUnavailable, "billing not enabled")
		return
	}
	pathSecret := chi.URLParam(r, "secret")
	headers := map[string]string{}
	for k, vs := range r.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}
	if pathSecret != "" {
		headers["X-Hash-Mollie-Path-Secret"] = pathSecret
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if err := s.Billing.HandleWebhook(r.Context(), raw, headers); err != nil {
		if errors.Is(err, billing.ErrInvalidWebhook) {
			writeError(w, http.StatusUnauthorized, "invalid webhook signature")
			return
		}
		if errors.Is(err, billing.ErrWebhookCorrelation) {
			// Mollie recommends returning success for an unknown ID to avoid
			// leaking which provider resources belong to this installation. The
			// engine made no mutation because strict correlation failed.
			w.WriteHeader(http.StatusOK)
			return
		}
		// Provider/DB failures are retryable. Mollie retries non-2xx
		// callbacks; classifying these as 400 permanently lost activation.
		writeError(w, http.StatusServiceUnavailable, "billing webhook processing temporarily unavailable")
		return
	}
	// Mollie's classic webhook contract explicitly expects 200 OK.
	w.WriteHeader(http.StatusOK)
}
