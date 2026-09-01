// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
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

	if w.pool == nil || w.audit == nil {
		slog.Warn("quota_warnings: atomic dependencies unavailable", "org_id", row.OrgID)
		return
	}
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		slog.Warn("quota_warnings: begin", "err", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Serialize all worker replicas on the subscription and recheck the period
	// marker under the lock. This prevents duplicate queue rows when two scans
	// observe the same warning candidate before either marks it.
	var lastSent, periodStart pgtype.Timestamptz
	if err := tx.QueryRow(ctx, `
		SELECT last_quota_warning_sent_at, current_period_start
		FROM org_subscriptions
		WHERE id = $1
		FOR UPDATE`, row.SubscriptionID).Scan(&lastSent, &periodStart); err != nil {
		slog.Warn("quota_warnings: lock subscription", "err", err)
		return
	}
	if lastSent.Valid && periodStart.Valid && !lastSent.Time.Before(periodStart.Time) {
		return
	}

	q := w.queries.WithTx(tx)
	for _, u := range users {
		if _, err := q.EnqueueEmailDelivery(ctx, generated.EnqueueEmailDeliveryParams{
			ToEmail: u.Email, Subject: subj, HtmlBody: html, TextBody: text, HeadersJson: []byte(`{}`),
		}); err != nil {
			slog.Warn("quota_warnings: enqueue", "to", dispatch.MaskEmail(u.Email), "err", dispatch.ScrubEmails(err.Error()))
			return
		}
	}
	if err := q.MarkQuotaWarningSent(ctx, row.SubscriptionID); err != nil {
		slog.Warn("quota_warnings: mark sent", "err", err)
		return
	}
	pending, err := w.audit.LogTx(ctx, tx, audit.Entry{
		OrgID: row.OrgID,
		Kind:  audit.KindBillingQuotaWarning80,
		Payload: map[string]any{
			"plan":       row.PlanSlug,
			"quota_kind": quotaKind,
			"used":       used,
			"limit":      limit,
			"pct":        pct,
			"recipients": len(users),
		},
	})
	if err != nil {
		slog.Warn("quota_warnings: audit", "err", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		slog.Warn("quota_warnings: commit", "err", err)
		return
	}
	w.audit.Publish(pending)
	if len(users) == 0 {
		slog.Info("quota_warnings: no users on org, marked for period", "org_id", row.OrgID)
	}
}

// pickTrippedQuota returns whichever quota has crossed the threshold,
// preferring documents on ties since that's the cap most users hit
// first. Returns ("", 0, 0, 0) when neither quota actually trips
// (shouldn't happen given the SQL filter, but kept defensively).
func pickTrippedQuota(row *generated.ListSubscriptionsOverQuotaWarningRow, thresholdPct int) (string, int32, int32, int) {
	if row.DocumentQuotaMonthly > 0 {
		pct := int(int64(row.DocumentsUsed) * 100 / int64(row.DocumentQuotaMonthly))
		if pct >= thresholdPct {
			return "documents", row.DocumentsUsed, row.DocumentQuotaMonthly, pct
		}
	}
	if row.RecipientQuotaMonthly > 0 {
		pct := int(int64(row.RecipientsUsed) * 100 / int64(row.RecipientQuotaMonthly))
		if pct >= thresholdPct {
			return "recipients", row.RecipientsUsed, row.RecipientQuotaMonthly, pct
		}
	}
	return "", 0, 0, 0
}
