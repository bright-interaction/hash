package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/brightinteraction/hash/internal/dispatch"
)

// renderEmailForMCP returns the closure the MCP workflow tools call to ship
// invite + reminder emails. Lives in cmd/server so the MCP package can
// stay HTML-template-free.
//
// orgName is the human-readable org name surfaced in templates (we don't
// have a per-org branding system yet; production sets a single org name
// per Hash instance).
func renderEmailForMCP(orgName string) func(m dispatch.Mailer, kind, toEmail, toName, docName, senderEmail, signURL, beaconURL string) {
	return func(m dispatch.Mailer, kind, toEmail, toName, docName, senderEmail, signURL, beaconURL string) {
		if m == nil {
			return
		}
		subj, html, text, err := dispatch.Render(kind, dispatch.TemplateContext{
			DocumentName:  docName,
			SenderName:    senderEmail,
			SenderEmail:   senderEmail,
			RecipientName: toName,
			OrgName:       orgName,
			SignURL:       signURL,
			BeaconURL:     beaconURL,
		})
		if err != nil {
			slog.Warn("mcp email render failed", "kind", kind, "err", err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := m.Send(ctx, dispatch.Message{
			To: toEmail, Subject: subj, HTML: html, Text: text,
		}); err != nil {
			slog.Warn("mcp email send failed", "kind", kind, "to", toEmail, "err", err)
		}
	}
}
