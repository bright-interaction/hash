// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package dispatch fans Hash events out to email + webhook destinations.
//
// SMTP is intentionally implemented against the stdlib's net/smtp to keep
// the dependency graph small. Postal (mail.brightinteraction.com) is the
// production target; in local dev + CI we point at mailhog (port 1025) so
// e2e tests can assert that emails landed.
package dispatch

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// SMTPConfig is the slice of hash config the dispatcher needs.
type SMTPConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	From     string // RFC-5322 From header, e.g. `Hash <esign@brightinteraction.com>`
}

// Mailer sends transactional email. Real implementations connect to Postal
// or mailhog; tests substitute a recording stub.
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

// Message carries everything we need to ship an email.
type Message struct {
	To      string
	Subject string
	HTML    string
	Text    string // plaintext alternative; required for spam-folder hygiene
	// ReplyTo is the human sender's address (so replies reach them, not the
	// no-reply From). Empty for system mail.
	ReplyTo string
	// FromName overrides the From display name (per-org branding). Empty keeps
	// the instance default. The envelope/addr-spec always stays the
	// authenticated instance address for SPF/DKIM/DMARC alignment.
	FromName string
	Headers  map[string]string
}

// SMTPMailer is the production implementation. Zero allocation surprises:
// each Send opens a fresh connection, authenticates, ships, closes. Reuse
// arrives in week 5 once we measure the call rate.
type SMTPMailer struct {
	cfg SMTPConfig
}

const smtpOperationTimeout = 30 * time.Second

// NewSMTPMailer returns a real Postal/mailhog client. Returns an error if
// the configuration is incomplete enough that sending is guaranteed to
// fail (no host or no from).
func NewSMTPMailer(cfg SMTPConfig) (*SMTPMailer, error) {
	if cfg.Host == "" {
		return nil, errors.New("smtp host required")
	}
	if cfg.From == "" {
		return nil, errors.New("smtp from required")
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, errors.New("smtp port must be between 1 and 65535")
	}
	if (cfg.User == "") != (cfg.Password == "") {
		return nil, errors.New("smtp user and password must either both be set or both be empty")
	}
	from, err := mail.ParseAddress(cfg.From)
	if err != nil || from.Address == "" {
		return nil, errors.New("smtp from must be a valid RFC-5322 address")
	}
	return &SMTPMailer{cfg: cfg}, nil
}

// Send delivers msg via the configured server. STARTTLS is required on
// every non-1025 port; mailhog uses 1025 plain so local development can use
// that explicitly reserved exception.
// AUTH PLAIN is sent only if the config has a user + password set.
func (m *SMTPMailer) Send(ctx context.Context, msg Message) error {
	if msg.To == "" {
		return errors.New("smtp: message to required")
	}
	addr := net.JoinHostPort(m.cfg.Host, fmt.Sprintf("%d", m.cfg.Port))

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return smtpOperationError(ctx, "smtp dial", err)
	}
	// DialContext only bounds the TCP connect. The SMTP greeting, EHLO, TLS,
	// AUTH, and DATA exchanges would otherwise be allowed to stall forever
	// after a peer accepts the socket. Bound the whole transaction and close
	// the connection promptly when the caller cancels a context without a
	// deadline. The worker's 30-second send context remains the outer bound.
	deadline := time.Now().Add(smtpOperationTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return smtpOperationError(ctx, "smtp set connection deadline", err)
	}
	stopContextClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopContextClose()
	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return smtpOperationError(ctx, "smtp new client", err)
	}
	defer c.Close()

	// STARTTLS is mandatory outside the reserved local MailHog port. Merely
	// attempting it when advertised permits a stripping attacker to remove the
	// capability and receive both the message and AUTH PLAIN credentials.
	// Production config rejects port 1025; that exception is dev/e2e only.
	if m.cfg.Port != 1025 {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			if ctxErr := smtpContextError(ctx); ctxErr != nil {
				return fmt.Errorf("smtp hello: %w", ctxErr)
			}
			return errors.New("smtp: STARTTLS is required but the server did not advertise it")
		}
		if err := c.StartTLS(&tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return smtpOperationError(ctx, "smtp starttls", err)
		}
	}

	// Auth only when we have credentials. mailhog needs no auth.
	if m.cfg.User != "" && m.cfg.Password != "" {
		auth := smtp.PlainAuth("", m.cfg.User, m.cfg.Password, m.cfg.Host)
		if err := c.Auth(auth); err != nil {
			return smtpOperationError(ctx, "smtp auth", err)
		}
	}

	if err := c.Mail(extractAddress(m.cfg.From)); err != nil {
		return smtpOperationError(ctx, "smtp mail from", err)
	}
	if err := c.Rcpt(extractAddress(msg.To)); err != nil {
		return smtpOperationError(ctx, "smtp rcpt", err)
	}

	body, err := buildMIME(m.cfg.From, msg)
	if err != nil {
		return err
	}
	wc, err := c.Data()
	if err != nil {
		return smtpOperationError(ctx, "smtp data open", err)
	}
	if _, err := wc.Write([]byte(body)); err != nil {
		_ = wc.Close()
		return smtpOperationError(ctx, "smtp data write", err)
	}
	if err := wc.Close(); err != nil {
		return smtpOperationError(ctx, "smtp data close", err)
	}
	if err := c.Quit(); err != nil {
		return smtpOperationError(ctx, "smtp quit", err)
	}
	return nil
}

// smtpContextError closes the small scheduling gap between a socket deadline
// firing and the context timer goroutine publishing ctx.Err(). Without the
// deadline check, the same caller deadline can nondeterministically surface as
// a raw net.Error under race/load, which makes retry and shutdown policy unable
// to distinguish provider failure from caller cancellation.
func smtpContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func smtpOperationError(ctx context.Context, operation string, err error) error {
	if ctxErr := smtpContextError(ctx); ctxErr != nil {
		return fmt.Errorf("%s: %w", operation, ctxErr)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

// sanitizeHeaderValue removes CR/LF (and other control chars) from a header
// value so an attacker-controlled document/sender name can't inject extra
// headers or a body. Header continuation/folding is not needed for our short
// values, so dropping the control bytes entirely is the safe choice.
func sanitizeHeaderValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || (r < 0x20 && r != '\t') {
			return -1
		}
		return r
	}, s)
}

// buildMIME assembles a multipart/alternative message with both HTML and
// plaintext parts, plus any extra headers the caller specified.
func buildMIME(from string, msg Message) (string, error) {
	if msg.Subject == "" {
		return "", errors.New("smtp: subject required")
	}
	if msg.HTML == "" && msg.Text == "" {
		return "", errors.New("smtp: at least one of HTML or Text required")
	}
	if msg.Text == "" {
		msg.Text = stripHTML(msg.HTML)
	}

	boundary := fmt.Sprintf("hash-%d", time.Now().UnixNano())
	var sb strings.Builder
	// All header values are CRLF-stripped (header-injection defense) and the
	// Subject is RFC 2047 encoded; the From display name can be overridden
	// per-org while the addr-spec stays the authenticated instance address so
	// DMARC/DKIM/SPF still align.
	fromHeader := from
	if msg.FromName != "" {
		fromHeader = (&mail.Address{Name: sanitizeHeaderValue(msg.FromName), Address: extractAddress(from)}).String()
	}
	fmt.Fprintf(&sb, "From: %s\r\n", sanitizeHeaderValue(fromHeader))
	fmt.Fprintf(&sb, "To: %s\r\n", sanitizeHeaderValue(msg.To))
	if msg.ReplyTo != "" {
		fmt.Fprintf(&sb, "Reply-To: %s\r\n", sanitizeHeaderValue(msg.ReplyTo))
	}
	fmt.Fprintf(&sb, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", sanitizeHeaderValue(msg.Subject)))
	fmt.Fprintf(&sb, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&sb, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	for k, v := range msg.Headers {
		fmt.Fprintf(&sb, "%s: %s\r\n", sanitizeHeaderValue(k), sanitizeHeaderValue(v))
	}
	fmt.Fprintf(&sb, "Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary)
	fmt.Fprintf(&sb, "\r\n")

	fmt.Fprintf(&sb, "--%s\r\n", boundary)
	fmt.Fprintf(&sb, "Content-Type: text/plain; charset=UTF-8\r\n")
	fmt.Fprintf(&sb, "Content-Transfer-Encoding: 8bit\r\n\r\n")
	sb.WriteString(msg.Text)
	sb.WriteString("\r\n")

	fmt.Fprintf(&sb, "--%s\r\n", boundary)
	fmt.Fprintf(&sb, "Content-Type: text/html; charset=UTF-8\r\n")
	fmt.Fprintf(&sb, "Content-Transfer-Encoding: 8bit\r\n\r\n")
	sb.WriteString(msg.HTML)
	sb.WriteString("\r\n")

	fmt.Fprintf(&sb, "--%s--\r\n", boundary)
	return sb.String(), nil
}

// extractAddress pulls `tom@brightinteraction.com` out of `Tom <tom@..>`.
// MAIL FROM and RCPT TO need the bare address, not the friendly form.
func extractAddress(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "<"); i >= 0 {
		if j := strings.Index(s[i+1:], ">"); j >= 0 {
			return strings.TrimSpace(s[i+1 : i+1+j])
		}
	}
	return s
}

// stripHTML is the plaintext fallback. Best-effort: collapses tags + decodes
// the few entities that show up most often in transactional email. Not
// production-grade, but enough that recipients with HTML-disabled clients
// still get something readable.
func stripHTML(s string) string {
	var sb strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			sb.WriteRune(r)
		}
	}
	out := sb.String()
	out = strings.ReplaceAll(out, "&nbsp;", " ")
	out = strings.ReplaceAll(out, "&amp;", "&")
	out = strings.ReplaceAll(out, "&lt;", "<")
	out = strings.ReplaceAll(out, "&gt;", ">")
	out = strings.ReplaceAll(out, "&quot;", "\"")
	// Collapse runs of whitespace.
	fields := strings.Fields(out)
	return strings.Join(fields, " ")
}

// NoopMailer drops every message on the floor. Used when no SMTP host is
// configured so we don't crash a dev environment that has no mail backend.
type NoopMailer struct{}

func (NoopMailer) Send(_ context.Context, _ Message) error { return nil }

// RecordingMailer captures every Send call in memory. Used by tests.
type RecordingMailer struct {
	Sent []Message
}

func (m *RecordingMailer) Send(_ context.Context, msg Message) error {
	m.Sent = append(m.Sent, msg)
	return nil
}
