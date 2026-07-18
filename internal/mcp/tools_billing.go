// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"net/http"

	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/billing"
	"github.com/brightinteraction/hash/internal/db/generated"
)

// registerBillingTools mounts v1.1 Mollie billing observability for
// agents: list available plans, fetch the current org subscription,
// list invoices. No mutating tools - billing state changes go through
// the session-authed REST endpoints + provider webhook so an agent
// can't silently downgrade an org or trigger a checkout.
func registerBillingTools(s *Server, d Deps) {
	if d.Billing == nil {
		return
	}

	s.RegisterTool(ToolDef{
		Name:        "list_billing_plans",
		Description: "Return the active plan catalog (slug, name, prices in cents, document/recipient monthly quotas, feature flags). Useful for an agent advising on plan upgrades.",
		InputSchema: schemaObject(map[string]any{}, nil),
		Handler: func(r *http.Request, _ json.RawMessage) (any, error) {
			plans, err := d.Billing.ListPlans(r.Context())
			if err != nil {
				return nil, err
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
					"features":                json.RawMessage(p.FeaturesJson),
				})
			}
			return map[string]any{"plans": out, "count": len(out), "provider": d.Billing.Provider.Name()}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "get_org_subscription",
		Description: "Return the calling org's current billing subscription + plan: status, provider, period dates, cancel-at-period-end flag. Returns the free plan implied when no row exists. Useful for an agent that wants to gate behavior on plan features before suggesting a workflow.",
		InputSchema: schemaObject(map[string]any{}, nil),
		Handler: func(r *http.Request, _ json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			plan, sub, err := d.Billing.PlanForOrg(r.Context(), u.OrgID)
			if err != nil {
				return nil, err
			}
			out := map[string]any{}
			if plan != nil {
				out["plan"] = map[string]any{
					"slug":                    plan.Slug,
					"name":                    plan.Name,
					"document_quota_monthly":  plan.DocumentQuotaMonthly,
					"recipient_quota_monthly": plan.RecipientQuotaMonthly,
					"features":                json.RawMessage(plan.FeaturesJson),
				}
			}
			if sub != nil {
				subOut := map[string]any{
					"status":               sub.Status,
					"provider":             sub.Provider,
					"cancel_at_period_end": sub.CancelAtPeriodEnd,
				}
				if sub.CurrentPeriodStart.Valid {
					subOut["current_period_start"] = sub.CurrentPeriodStart.Time.UTC()
				}
				if sub.CurrentPeriodEnd.Valid {
					subOut["current_period_end"] = sub.CurrentPeriodEnd.Time.UTC()
				}
				out["subscription"] = subOut
			}
			return out, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "list_billing_invoices",
		Description: "Return the calling org's most recent billing invoices (default 50). Each row carries provider_payment_id, status, amount_cents, hosted invoice URL.",
		InputSchema: schemaObject(map[string]any{
			"limit": intSchema("max invoices (default 50, max 200)", 1, 200, 50),
		}, nil),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				Limit int `json:"limit"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			if p.Limit <= 0 {
				p.Limit = 50
			}
			if p.Limit > 200 {
				p.Limit = 200
			}
			rows, err := d.Queries.ListBillingInvoicesForOrg(r.Context(), generated.ListBillingInvoicesForOrgParams{
				OrgID: u.OrgID,
				Limit: int32(p.Limit),
			})
			if err != nil {
				return nil, err
			}
			out := make([]map[string]any, 0, len(rows))
			for _, inv := range rows {
				entry := map[string]any{
					"id":                  inv.ID.String(),
					"provider":            inv.Provider,
					"provider_payment_id": inv.ProviderPaymentID,
					"status":              inv.Status,
					"amount_cents":        inv.AmountCents,
					"currency":            inv.Currency,
					"created_at":          inv.CreatedAt.Time.UTC(),
				}
				if inv.PaidAt.Valid {
					entry["paid_at"] = inv.PaidAt.Time.UTC()
				}
				if inv.HostedInvoiceUrl.Valid {
					entry["hosted_invoice_url"] = inv.HostedInvoiceUrl.String
				}
				out = append(out, entry)
			}
			return map[string]any{"invoices": out, "count": len(out)}, nil
		},
	})
}

// keep the billing import alive even if the tool set evolves.
var _ = billing.ErrPlanNotFound
