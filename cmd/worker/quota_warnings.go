package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/dispatch"
)

// loopQuotaWarnings emails an org at most once per billing period when
// usage on any quota crosses 80%. Closes the v1 UX gap where the only
// signal a customer got was a 402 the moment they hit the cap.

const (
	quotaWarningInterval  = 6 * time.Hour
	quotaWarningThreshold = 80 // percent
)

func (w *worker) loopQuotaWarnings(ctx context.Context) {
	tick := time.NewTicker(quotaWarningInterval)
	defer tick.Stop()
	w.runQuotaWarningsOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runQuotaWarningsOnce(ctx)
		}
	}
}

func (w *worker) runQuotaWarningsOnce(ctx context.Context) {
	rows, err := w.queries.ListSubscriptionsOverQuotaWarning(ctx, quotaWarningThreshold)
	if err != nil {
		slog.Warn("quota_warnings: list", "err", err)
		return
	}
	for _, row := range rows {
		w.sendQuotaWarning(ctx, row)
	}
}

// sendQuotaWarning picks the quota that tripped first (documents wins
// ties), emails every user on the org, then marks the subscription so
// the next tick within the same billing period skips it.
func (w *worker) sendQuotaWarning(ctx context.Context, row *generated.ListSubscriptionsOverQuotaWarningRow) {
	if row == nil {
		return
	}
	quotaKind, used, limit, pct := pickTrippedQuota(row, quotaWarningThreshold)
	if quotaKind == "" {
		return
	}
	org, err := w.queries.GetOrg(ctx, row.OrgID)
	if err != nil {
		slog.Warn("quota_warnings: load org", "org_id", row.OrgID, "err", err)
		return
	}
	users, err := w.queries.ListUsersByOrg(ctx, row.OrgID)
	if err != nil {
		slog.Warn("quota_warnings: list users", "org_id", row.OrgID, "err", err)
		return
	}
	if len(users) == 0 {
		slog.Info("quota_warnings: no users on org, skipping", "org_id", row.OrgID)
		// Still mark sent so we don't re-scan this row every tick for an
		// org with no logins.
		_ = w.queries.MarkQuotaWarningSent(ctx, row.SubscriptionID)
		return
	}

	periodResetAt := ""
	if row.CurrentPeriodEnd.Valid {
		periodResetAt = row.CurrentPeriodEnd.Time.UTC().Format("January 2, 2006")
	}

	tplCtx := dispatch.TemplateContext{
		OrgName:       org.Name,
		PlanName:      row.PlanName,
		QuotaKind:     quotaKind,
		QuotaUsed:     int(used),
		QuotaLimit:    int(limit),
		QuotaPct:      pct,
		PeriodResetAt: periodResetAt,
		UpgradeURL:    w.baseURL + "/settings/billing",
	}
	subj, html, text, err := dispatch.Render(dispatch.KindQuotaWarning80, tplCtx)
	if err != nil {
		slog.Warn("quota_warnings: render", "err", err)
		return
	}

	for _, u := range users {
		mctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := w.mailer.Send(mctx, dispatch.Message{To: u.Email, Subject: subj, HTML: html, Text: text}); err != nil {
			slog.Warn("quota_warnings: send", "to", u.Email, "err", err)
		}
		cancel()
	}

	if err := w.queries.MarkQuotaWarningSent(ctx, row.SubscriptionID); err != nil {
		slog.Warn("quota_warnings: mark sent", "err", err)
		return
	}
	_, _ = w.audit.Log(ctx, audit.Entry{
		OrgID: row.OrgID,
		Kind:  audit.KindBillingQuotaWarning80,
		Payload: map[string]any{
			"plan":       row.PlanSlug,
			"quota_kind": quotaKind,
			"used":       used,
			"limit":      limit,
			"pct":        pct,
		},
	})
}

// pickTrippedQuota returns whichever quota has crossed the threshold,
// preferring documents on ties since that's the cap most users hit
// first. Returns ("", 0, 0, 0) when neither quota actually trips
// (shouldn't happen given the SQL filter, but kept defensively).
func pickTrippedQuota(row *generated.ListSubscriptionsOverQuotaWarningRow, thresholdPct int) (string, int32, int32, int) {
	if row.DocumentQuotaMonthly > 0 {
		pct := int(int64(row.DocumentsUsed)*100 / int64(row.DocumentQuotaMonthly))
		if pct >= thresholdPct {
			return "documents", row.DocumentsUsed, row.DocumentQuotaMonthly, pct
		}
	}
	if row.RecipientQuotaMonthly > 0 {
		pct := int(int64(row.RecipientsUsed)*100 / int64(row.RecipientQuotaMonthly))
		if pct >= thresholdPct {
			return "recipients", row.RecipientsUsed, row.RecipientQuotaMonthly, pct
		}
	}
	return "", 0, 0, 0
}
