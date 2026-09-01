// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"github.com/bright-interaction/hash/internal/i18n"
)

// Template kinds Hash can send. Values match `events.kind` so the same
// enum drives the audit log and the dispatcher.
const (
	KindInvite           = "email.invite"
	KindReminder         = "email.reminder"
	KindCompletedSigner  = "email.completed_signer"
	KindCompletedSender  = "email.completed_sender"
	KindDeclined         = "email.declined"
	KindChangesRequested = "email.changes_requested"
	KindNewComment       = "email.new_comment"
	KindVoided           = "email.voided"
	KindQuotaWarning80   = "email.quota_warning_80"
)

// TemplateContext is everything every email needs to render. Optional
// fields (DownloadURL, DeclineReason) are empty strings when not relevant.
type TemplateContext struct {
	DocumentName  string
	SenderName    string
	SenderEmail   string
	RecipientName string
	OrgName       string
	Locale        string // recipient locale for invite/reminder/completed_signer; empty = English
	SignURL       string // signer-side magic link (for invite/reminder)
	// BeaconURL is retained only for source compatibility with older callers.
	// Recipient-identifiable pre-notice email tracking is disabled: invite and
	// reminder renderers deliberately ignore this value and never emit an image.
	BeaconURL   string
	DownloadURL string // for completed_signer/sender
	// DownloadExpiresAt is the exact UTC deadline shown to external recipients.
	// Completion rendering fails closed without it so credential TTL and copy
	// cannot silently drift.
	DownloadExpiresAt string
	// Acknowledgement selects no-signature ceremony copy for recipient and
	// sender lifecycle emails.
	Acknowledgement bool
	DeclineReason   string // for declined; reused as the change comment for changes_requested
	BrandColor      string // optional accent; default to black

	// Inline change-request snippet (for changes_requested).
	ChangeQuote    string // the marked text
	ChangeContext  string // the surrounding paragraph
	ChangeProposed string // optional proposed replacement
	OpenURL        string // deep link to the document in the app
	ApproveURL     string // one-click approve link (signed action token)
	DenyURL        string // one-click deny link (signed action token)

	// Quota warning fields. Empty for non-billing templates.
	QuotaKind     string // "documents" or "recipients"
	QuotaUsed     int
	QuotaLimit    int
	QuotaPct      int    // 80, 90, etc., already rounded
	PeriodResetAt string // human-readable date
	UpgradeURL    string // dashboard link to upgrade plan
	PlanName      string
}

// Render returns (subject, html, text) for the given kind + ctx. Errors only
// when the kind is unknown or templates fail to compile.
func Render(kind string, ctx TemplateContext) (subject, html, text string, err error) {
	if kind == KindCompletedSigner && strings.TrimSpace(ctx.DownloadExpiresAt) == "" {
		return "", "", "", fmt.Errorf("completed recipient email requires download expiry")
	}
	subj, err := renderSubject(kind, ctx)
	if err != nil {
		return "", "", "", err
	}
	htmlBody, err := renderHTMLTemplate(kind, ctx)
	if err != nil {
		return "", "", "", err
	}
	textBody, err := renderTextTemplate(kind, ctx)
	if err != nil {
		return "", "", "", err
	}
	return subj, htmlBody, textBody, nil
}

func renderSubject(kind string, ctx TemplateContext) (string, error) {
	if recipientLocalized(kind) {
		return localizedSubject(kind, ctx), nil
	}
	switch kind {
	case KindInvite:
		return fmt.Sprintf("%s sent you %s for signature", ctx.SenderName, ctx.DocumentName), nil
	case KindReminder:
		return fmt.Sprintf("Reminder: %s is awaiting your signature", ctx.DocumentName), nil
	case KindCompletedSigner:
		return fmt.Sprintf("Your signed copy of %s", ctx.DocumentName), nil
	case KindCompletedSender:
		if ctx.Acknowledgement {
			return fmt.Sprintf("%s acknowledgements complete", ctx.DocumentName), nil
		}
		return fmt.Sprintf("%s signing ceremony complete", ctx.DocumentName), nil
	case KindDeclined:
		return fmt.Sprintf("%s declined %s", ctx.RecipientName, ctx.DocumentName), nil
	case KindChangesRequested:
		return fmt.Sprintf("%s requested changes to %s", ctx.RecipientName, ctx.DocumentName), nil
	case KindNewComment:
		return fmt.Sprintf("New comment on %s", ctx.DocumentName), nil
	case KindVoided:
		return fmt.Sprintf("%s was voided", ctx.DocumentName), nil
	case KindQuotaWarning80:
		return fmt.Sprintf("Heads up: %s usage at %d%% on the %s plan", ctx.QuotaKind, ctx.QuotaPct, ctx.PlanName), nil
	}
	return "", fmt.Errorf("unknown template kind: %s", kind)
}

// renderHTMLTemplate compiles the per-kind HTML template against ctx.
// Templates live inline in this file (see the const block below); design
// rationale: keep the binary self-contained so a misconfigured embed FS
// can't ever silently ship empty emails.
func renderHTMLTemplate(kind string, ctx TemplateContext) (string, error) {
	if recipientLocalized(kind) {
		return localizedHTML(kind, ctx), nil
	}
	src := htmlFor(kind)
	if src == "" {
		return "", fmt.Errorf("no html template for %s", kind)
	}
	tpl, err := template.New(kind).Parse(src)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, ctx); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func renderTextTemplate(kind string, ctx TemplateContext) (string, error) {
	if recipientLocalized(kind) {
		return localizedText(kind, ctx), nil
	}
	src := textFor(kind)
	if src == "" {
		return "", fmt.Errorf("no text template for %s", kind)
	}
	tpl, err := template.New(kind).Parse(src)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, ctx); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// --- Recipient-locale rendering -------------------------------------------
//
// invite / reminder / completed_signer go to the external counterparty, so
// they render in the recipient's locale from the i18n catalog (English
// fallback per key). Sender-facing emails stay English. The HTML skeleton is
// shared; only the prose comes from the catalog, so there is no per-language
// HTML to break.

func recipientLocalized(kind string) bool {
	switch kind {
	case KindInvite, KindReminder, KindCompletedSigner:
		return true
	}
	return false
}

func catalogPrefix(kind string, ctx TemplateContext) string {
	switch kind {
	case KindInvite:
		if ctx.Acknowledgement {
			return "email.inviteAcknowledgement"
		}
		return "email.invite"
	case KindReminder:
		if ctx.Acknowledgement {
			return "email.reminderAcknowledgement"
		}
		return "email.reminder"
	case KindCompletedSigner:
		if ctx.Acknowledgement {
			return "email.completedAcknowledgement"
		}
		return "email.completedSigner"
	}
	return ""
}

func emailParams(ctx TemplateContext) map[string]string {
	return map[string]string{
		"sender":     ctx.SenderName,
		"email":      ctx.SenderEmail,
		"document":   ctx.DocumentName,
		"recipient":  ctx.RecipientName,
		"org":        ctx.OrgName,
		"expires_at": ctx.DownloadExpiresAt,
	}
}

// ctaURL is the action link: the signed-PDF download for completed_signer, the
// magic link otherwise.
func ctaURL(kind string, ctx TemplateContext) string {
	if kind == KindCompletedSigner {
		return ctx.DownloadURL
	}
	return ctx.SignURL
}

// footerKey is the catalog key for a kind's footer. Invites deliberately use
// the factual common footer: deployment/data-flow review, not an email
// template, determines whether a hosted instance may claim EU sovereignty.
func footerKey(kind string, ctx TemplateContext) string {
	if kind == KindInvite || kind == KindReminder {
		return "email.common.footer"
	}
	return catalogPrefix(kind, ctx) + ".footer"
}

func localizedSubject(kind string, ctx TemplateContext) string {
	return i18n.T(i18n.Normalize(ctx.Locale), catalogPrefix(kind, ctx)+".subject", emailParams(ctx))
}

func localizedHTML(kind string, ctx TemplateContext) string {
	loc := i18n.Normalize(ctx.Locale)
	p := emailParams(ctx)
	prefix := catalogPrefix(kind, ctx)
	esc := template.HTMLEscapeString
	eyebrow := esc(i18n.T(loc, prefix+".eyebrow", p))
	heading := esc(i18n.T(loc, prefix+".heading", p))
	body := esc(i18n.T(loc, prefix+".body", p))
	cta := esc(i18n.T(loc, prefix+".cta", p))
	footer := esc(i18n.T(loc, footerKey(kind, ctx), p))
	url := ctaURL(kind, ctx)
	urlEsc := esc(url)

	ctaBlock := ""
	if url != "" {
		ctaBlock = fmt.Sprintf(`<p style="margin: 24px 0;"><a href="%s" style="background: #111; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">%s</a></p>`, urlEsc, cta)
	}
	extra := ""
	if kind == KindInvite {
		orOpen := esc(i18n.T(loc, "email.common.orOpenUrl", p))
		extra = fmt.Sprintf(`<p style="font-size: 13px; color: #666;">%s <a href="%s">%s</a></p>`, orOpen, urlEsc, urlEsc)
	}
	return fmt.Sprintf(`<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">%s</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">%s</h1>
<p>%s</p>
%s
%s
<p style="font-size: 11px; color: #999; margin-top: 32px;">%s</p>
</body></html>`, eyebrow, heading, body, ctaBlock, extra, footer)
}

func localizedText(kind string, ctx TemplateContext) string {
	loc := i18n.Normalize(ctx.Locale)
	p := emailParams(ctx)
	prefix := catalogPrefix(kind, ctx)
	heading := i18n.T(loc, prefix+".heading", p)
	body := i18n.T(loc, prefix+".body", p)
	cta := i18n.T(loc, prefix+".cta", p)
	footer := i18n.T(loc, footerKey(kind, ctx), p)
	url := ctaURL(kind, ctx)
	if url == "" {
		return fmt.Sprintf("%s\n\n%s\n\n%s\n", heading, body, footer)
	}
	return fmt.Sprintf("%s\n\n%s\n\n%s: %s\n\n%s\n", heading, body, cta, url, footer)
}

func htmlFor(kind string) string {
	switch kind {
	case KindInvite:
		return inviteHTML
	case KindReminder:
		return reminderHTML
	case KindCompletedSigner:
		return completedSignerHTML
	case KindCompletedSender:
		return completedSenderHTML
	case KindDeclined:
		return declinedHTML
	case KindChangesRequested:
		return changesRequestedHTML
	case KindNewComment:
		return newCommentHTML
	case KindVoided:
		return voidedHTML
	case KindQuotaWarning80:
		return quotaWarning80HTML
	}
	return ""
}

func textFor(kind string) string {
	switch kind {
	case KindInvite:
		return inviteText
	case KindReminder:
		return reminderText
	case KindCompletedSigner:
		return completedSignerText
	case KindCompletedSender:
		return completedSenderText
	case KindDeclined:
		return declinedText
	case KindChangesRequested:
		return changesRequestedText
	case KindNewComment:
		return newCommentText
	case KindVoided:
		return voidedText
	case KindQuotaWarning80:
		return quotaWarning80Text
	}
	return ""
}

// Inline fallbacks. Same content the embedded files hold, kept here so the
// dispatcher works even if the embed path is misconfigured. Heavy duty
// HTML email styling stays minimal ,  most clients strip CSS anyway.

const inviteHTML = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
{{if .Acknowledgement}}
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Acknowledgement requested</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.SenderName}} sent you {{.DocumentName}}</h1>
<p>{{.SenderName}} ({{.SenderEmail}}) is asking you to review and acknowledge <strong>{{.DocumentName}}</strong>. No signature will be requested.</p>
<p style="margin: 24px 0;"><a href="{{.SignURL}}" style="background: #111; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Review and acknowledge</a></p>
{{else}}
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Signature requested</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.SenderName}} sent you {{.DocumentName}}</h1>
<p>{{.SenderName}} ({{.SenderEmail}}) is asking for your signature on <strong>{{.DocumentName}}</strong>.</p>
<p style="margin: 24px 0;"><a href="{{.SignURL}}" style="background: #111; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Review and sign</a></p>
{{end}}
<p style="font-size: 13px; color: #666;">Or open this URL: <a href="{{.SignURL}}">{{.SignURL}}</a></p>
<p style="font-size: 11px; color: #999; margin-top: 32px;">Sent via Hash for {{.OrgName}}.</p>
</body></html>`

const inviteText = `{{if .Acknowledgement}}{{.SenderName}} sent you {{.DocumentName}} to review and acknowledge. No signature will be requested.

Open this URL to review and acknowledge:
{{else}}{{.SenderName}} sent you {{.DocumentName}} for signature.

Open this URL to review and sign:
{{end}}
{{.SignURL}}

Sent via Hash for {{.OrgName}}.
`

const reminderHTML = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Reminder</p>
{{if .Acknowledgement}}
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.DocumentName}} still awaits your acknowledgement</h1>
<p>Hi {{.RecipientName}}, just a reminder that {{.SenderName}} is waiting for you to review and acknowledge this document. No signature will be requested.</p>
<p style="margin: 24px 0;"><a href="{{.SignURL}}" style="background: #111; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Review and acknowledge</a></p>
{{else}}
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.DocumentName}} still awaiting your signature</h1>
<p>Hi {{.RecipientName}}, just a reminder that {{.SenderName}} is still waiting on your signature.</p>
<p style="margin: 24px 0;"><a href="{{.SignURL}}" style="background: #111; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Open and sign</a></p>
{{end}}
<p style="font-size: 11px; color: #999; margin-top: 32px;">Sent via Hash for {{.OrgName}}.</p>
</body></html>`

const reminderText = `{{if .Acknowledgement}}Reminder: {{.DocumentName}} still awaits your acknowledgement.

Review and acknowledge: {{.SignURL}}
{{else}}Reminder: {{.DocumentName}} is still awaiting your signature.

Open and sign: {{.SignURL}}
{{end}}
`

const completedSignerHTML = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Signed</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">Your signed copy of {{.DocumentName}}</h1>
<p>The signing ceremony is complete. Use the link below to download and save the completed signed PDF before {{.DownloadExpiresAt}}. The link does not include the separately stored audit certificate.</p>
{{if .DownloadURL}}<p style="margin: 24px 0;"><a href="{{.DownloadURL}}" style="background: #111; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Download signed PDF</a></p>{{end}}
<p style="font-size: 11px; color: #999; margin-top: 32px;">Sent via Hash for {{.OrgName}}.</p>
</body></html>`

const completedSignerText = `The completed signed PDF for {{.DocumentName}} is ready. The download link expires at {{.DownloadExpiresAt}} and does not include the separately stored audit certificate.

Download: {{.DownloadURL}}
`

const completedSenderHTML = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Completed</p>
{{if .Acknowledgement}}
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.DocumentName}} acknowledgements are complete</h1>
<p>All required recipients acknowledged the document. The completed PDF contains no signature image or representation that a party signed. The separately stored audit certificate records acknowledgement evidence and is not included in this download.</p>
{{else}}
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.DocumentName}} signing ceremony is complete</h1>
<p>All required signing roles completed. The final signed PDF is ready; the audit certificate is stored separately and is not included in this download.</p>
{{end}}
{{if .DownloadURL}}<p style="margin: 24px 0;"><a href="{{.DownloadURL}}" style="background: #111; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Download completed PDF</a></p>{{end}}
</body></html>`

const completedSenderText = `{{if .Acknowledgement}}All required acknowledgements for {{.DocumentName}} are complete. The PDF contains no signature image or representation that a party signed; the acknowledgement audit certificate is stored separately and is not included in this download.{{else}}All required signing roles for {{.DocumentName}} completed. The audit certificate is stored separately and is not included in this download.{{end}}
Download completed PDF: {{.DownloadURL}}
`

const declinedHTML = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Declined</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.RecipientName}} declined {{.DocumentName}}</h1>
{{if .DeclineReason}}<p>Reason given:</p><blockquote style="border-left: 3px solid #ccc; padding-left: 12px; color: #555;">{{.DeclineReason}}</blockquote>{{end}}
<p>The document has been moved to declined state. No further signers will be invited.</p>
</body></html>`

const declinedText = `{{.RecipientName}} declined {{.DocumentName}}.
{{if .DeclineReason}}Reason: {{.DeclineReason}}{{end}}
`

const changesRequestedHTML = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Changes requested</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.RecipientName}} requested changes to {{.DocumentName}}</h1>
{{if .ChangeContext}}<p style="font-size: 13px; color: #777; margin-bottom: 4px;">In context:</p><p style="color: #555; font-size: 13px; line-height: 1.5;">{{.ChangeContext}}</p>{{end}}
{{if .ChangeQuote}}<p style="font-size: 13px; color: #777; margin: 12px 0 4px;">Marked text:</p><blockquote style="border-left: 3px solid #0891B2; padding-left: 12px; color: #111; font-weight: 500;">{{.ChangeQuote}}</blockquote>{{end}}
{{if .DeclineReason}}<p style="font-size: 13px; color: #777; margin: 12px 0 4px;">Their comment:</p><blockquote style="border-left: 3px solid #ccc; padding-left: 12px; color: #555;">{{.DeclineReason}}</blockquote>{{end}}
{{if .ChangeProposed}}<p style="font-size: 13px; color: #777; margin: 12px 0 4px;">Proposed text:</p><blockquote style="border-left: 3px solid #16a34a; padding-left: 12px; color: #111;">{{.ChangeProposed}}</blockquote>{{end}}
<p style="margin-top: 20px;">
{{if .ApproveURL}}<a href="{{.ApproveURL}}" style="display: inline-block; background: #16a34a; color: #fff; text-decoration: none; padding: 10px 16px; border-radius: 6px; font-weight: 600; margin-right: 8px;">Approve</a>{{end}}
{{if .DenyURL}}<a href="{{.DenyURL}}" style="display: inline-block; background: #b91c1c; color: #fff; text-decoration: none; padding: 10px 16px; border-radius: 6px; font-weight: 600; margin-right: 8px;">Deny</a>{{end}}
<a href="{{.OpenURL}}" style="display: inline-block; background: #0891B2; color: #fff; text-decoration: none; padding: 10px 16px; border-radius: 6px; font-weight: 600;">Open document</a>
</p>
<p style="font-size: 12px; color: #999;">Signing is paused until you revise and re-send.</p>
</body></html>`

const changesRequestedText = `{{.RecipientName}} requested changes to {{.DocumentName}}.
{{if .ChangeContext}}In context: {{.ChangeContext}}{{end}}
{{if .ChangeQuote}}Marked text: {{.ChangeQuote}}{{end}}
{{if .DeclineReason}}Comment: {{.DeclineReason}}{{end}}
{{if .ChangeProposed}}Proposed: {{.ChangeProposed}}{{end}}
{{if .ApproveURL}}Approve: {{.ApproveURL}}{{end}}
{{if .DenyURL}}Deny: {{.DenyURL}}{{end}}
Open document: {{.OpenURL}}
`

const newCommentHTML = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">New comment</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.RecipientName}} commented on {{.DocumentName}}</h1>
<blockquote style="border-left: 3px solid #0891B2; padding-left: 12px; color: #555; white-space: pre-wrap;">{{.DeclineReason}}</blockquote>
{{if .OpenURL}}<p style="margin-top: 20px;"><a href="{{.OpenURL}}" style="display: inline-block; background: #0891B2; color: #fff; text-decoration: none; padding: 10px 18px; border-radius: 6px; font-weight: 600;">Open the document to reply</a></p>{{else}}<p style="margin-top: 16px; color: #777;">Open the signing link from your invitation or reminder, review the current privacy notice, and reply there.</p>{{end}}
</body></html>`

const newCommentText = `{{.RecipientName}} commented on {{.DocumentName}}:
{{.DeclineReason}}
{{if .OpenURL}}Reply: {{.OpenURL}}{{else}}Open the signing link from your invitation or reminder, review the current privacy notice, and reply there.{{end}}
`

const voidedHTML = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Voided</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.DocumentName}} was voided</h1>
<p>{{.SenderName}} voided this document. No signatures will be collected.</p>
</body></html>`

const voidedText = `{{.DocumentName}} was voided by {{.SenderName}}.
`

const quotaWarning80HTML = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Plan usage</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.OrgName}} is at {{.QuotaPct}}% of the {{.PlanName}} {{.QuotaKind}} quota</h1>
<p>You've used <strong>{{.QuotaUsed}} of {{.QuotaLimit}}</strong> {{.QuotaKind}} this billing period. The counter resets on <strong>{{.PeriodResetAt}}</strong>.</p>
<p>Hitting the cap pauses new sends until the next period. Upgrade now to avoid an interruption.</p>
{{if .UpgradeURL}}<p style="margin: 24px 0;"><a href="{{.UpgradeURL}}" style="background: #111; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Review plan</a></p>{{end}}
<p style="font-size: 11px; color: #999; margin-top: 32px;">Sent via Hash. You'll receive at most one of these per billing period.</p>
</body></html>`

const quotaWarning80Text = `{{.OrgName}} is at {{.QuotaPct}}% of the {{.PlanName}} {{.QuotaKind}} quota.

Used: {{.QuotaUsed}} of {{.QuotaLimit}} {{.QuotaKind}} this period.
Period resets: {{.PeriodResetAt}}

Review or upgrade: {{.UpgradeURL}}
`
