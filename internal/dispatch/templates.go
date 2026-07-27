// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"bytes"
	"fmt"
	"html/template"

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
	BeaconURL     string // 1×1 GIF beacon for `document.opened` tracking
	DownloadURL   string // for completed_signer/sender
	DeclineReason string // for declined; reused as the change comment for changes_requested
	BrandColor    string // optional accent; default to black

	// Inline change-request snippet (for changes_requested).
	ChangeQuote    string // the marked text
	ChangeContext  string // the surrounding paragraph
	ChangeProposed string // optional proposed replacement
	OpenURL        string // deep link to the document in the app
	ApproveURL     string // one-click approve link (signed action token)
	DenyURL        string // one-click deny link (signed action token)
	ReplyURL       string // one-click comment-reply link (signed action token)

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
		return fmt.Sprintf("%s signed by all parties", ctx.DocumentName), nil
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

func catalogPrefix(kind string) string {
	switch kind {
	case KindInvite:
		return "email.invite"
	case KindReminder:
		return "email.reminder"
	case KindCompletedSigner:
		return "email.completedSigner"
	}
	return ""
}

func emailParams(ctx TemplateContext) map[string]string {
	return map[string]string{
		"sender":    ctx.SenderName,
		"email":     ctx.SenderEmail,
		"document":  ctx.DocumentName,
		"recipient": ctx.RecipientName,
		"org":       ctx.OrgName,
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

// footerKey is the catalog key for a kind's footer; reminder reuses the common
// footer (it has no dedicated one).
func footerKey(kind string) string {
	if kind == KindReminder {
		return "email.common.footer"
	}
	return catalogPrefix(kind) + ".footer"
}

func localizedSubject(kind string, ctx TemplateContext) string {
	return i18n.T(i18n.Normalize(ctx.Locale), catalogPrefix(kind)+".subject", emailParams(ctx))
}

func localizedHTML(kind string, ctx TemplateContext) string {
	loc := i18n.Normalize(ctx.Locale)
	p := emailParams(ctx)
	prefix := catalogPrefix(kind)
	esc := template.HTMLEscapeString
	eyebrow := esc(i18n.T(loc, prefix+".eyebrow", p))
	heading := esc(i18n.T(loc, prefix+".heading", p))
	body := esc(i18n.T(loc, prefix+".body", p))
	cta := esc(i18n.T(loc, prefix+".cta", p))
	footer := esc(i18n.T(loc, footerKey(kind), p))
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
	beacon := ""
	if ctx.BeaconURL != "" {
		beacon = fmt.Sprintf(`<img src="%s" width="1" height="1" alt="" style="display:none">`, esc(ctx.BeaconURL))
	}
	return fmt.Sprintf(`<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">%s</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">%s</h1>
<p>%s</p>
%s
%s
<p style="font-size: 11px; color: #999; margin-top: 32px;">%s</p>
%s
</body></html>`, eyebrow, heading, body, ctaBlock, extra, footer, beacon)
}

func localizedText(kind string, ctx TemplateContext) string {
	loc := i18n.Normalize(ctx.Locale)
	p := emailParams(ctx)
	prefix := catalogPrefix(kind)
	heading := i18n.T(loc, prefix+".heading", p)
	body := i18n.T(loc, prefix+".body", p)
	cta := i18n.T(loc, prefix+".cta", p)
	footer := i18n.T(loc, footerKey(kind), p)
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
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Signature requested</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.SenderName}} sent you {{.DocumentName}}</h1>
<p>{{.SenderName}} ({{.SenderEmail}}) is asking for your signature on <strong>{{.DocumentName}}</strong>.</p>
<p style="margin: 24px 0;"><a href="{{.SignURL}}" style="background: #111; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Review and sign</a></p>
<p style="font-size: 13px; color: #666;">Or open this URL: <a href="{{.SignURL}}">{{.SignURL}}</a></p>
<p style="font-size: 11px; color: #999; margin-top: 32px;">Sent via Hash, EU-sovereign e-signing for {{.OrgName}}.</p>
{{if .BeaconURL}}<img src="{{.BeaconURL}}" width="1" height="1" alt="" style="display:none">{{end}}
</body></html>`

const inviteText = `{{.SenderName}} sent you {{.DocumentName}} for signature.

Open this URL to review and sign:
{{.SignURL}}

Sent via Hash for {{.OrgName}}.
`

const reminderHTML = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Reminder</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.DocumentName}} still awaiting your signature</h1>
<p>Hi {{.RecipientName}}, just a reminder that {{.SenderName}} is still waiting on your signature.</p>
<p style="margin: 24px 0;"><a href="{{.SignURL}}" style="background: #111; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Open and sign</a></p>
<p style="font-size: 11px; color: #999; margin-top: 32px;">Sent via Hash for {{.OrgName}}.</p>
{{if .BeaconURL}}<img src="{{.BeaconURL}}" width="1" height="1" alt="" style="display:none">{{end}}
</body></html>`

const reminderText = `Reminder: {{.DocumentName}} is still awaiting your signature.

Open and sign: {{.SignURL}}
`

const completedSignerHTML = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Signed</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">Your signed copy of {{.DocumentName}}</h1>
<p>The document has been signed by all parties. Your copy is attached below.</p>
{{if .DownloadURL}}<p style="margin: 24px 0;"><a href="{{.DownloadURL}}" style="background: #111; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Download signed PDF</a></p>{{end}}
<p style="font-size: 11px; color: #999; margin-top: 32px;">Sent via Hash for {{.OrgName}}. Keep this email; the audit certificate is bundled with the PDF.</p>
</body></html>`

const completedSignerText = `Your signed copy of {{.DocumentName}} is ready.

Download: {{.DownloadURL}}
`

const completedSenderHTML = `<!doctype html>
<html><body style="font-family: Inter, -apple-system, sans-serif; color: #111; padding: 24px; max-width: 560px;">
<p style="font-family: monospace; text-transform: uppercase; font-size: 11px; letter-spacing: 0.2em; color: #777;">Completed</p>
<h1 style="font-weight: 200; font-size: 24px; margin: 8px 0 16px;">{{.DocumentName}} is fully signed</h1>
<p>All recipients have signed. The final PDF + audit certificate are ready to download.</p>
{{if .DownloadURL}}<p style="margin: 24px 0;"><a href="{{.DownloadURL}}" style="background: #111; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">Download final PDF</a></p>{{end}}
</body></html>`

const completedSenderText = `{{.DocumentName}} is signed by all parties. Download: {{.DownloadURL}}
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
{{if .OpenURL}}<p style="margin-top: 20px;"><a href="{{.OpenURL}}" style="display: inline-block; background: #0891B2; color: #fff; text-decoration: none; padding: 10px 18px; border-radius: 6px; font-weight: 600;">Open the document to reply</a></p>{{else if .ReplyURL}}<p style="margin-top: 20px;"><a href="{{.ReplyURL}}" style="display: inline-block; background: #0891B2; color: #fff; text-decoration: none; padding: 10px 18px; border-radius: 6px; font-weight: 600;">Reply</a></p>{{else}}<p style="margin-top: 16px; color: #777;">Open the signing link from your invitation to reply.</p>{{end}}
</body></html>`

const newCommentText = `{{.RecipientName}} commented on {{.DocumentName}}:
{{.DeclineReason}}
{{if .OpenURL}}Reply: {{.OpenURL}}{{else if .ReplyURL}}Reply: {{.ReplyURL}}{{else}}Open the signing link from your invitation to reply.{{end}}
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
