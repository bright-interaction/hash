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
	return &SMTPMailer{cfg: cfg}, nil
}

// Send delivers msg via the configured server. STARTTLS is attempted on
// any non-1025 port; mailhog uses 1025 plain so we let that case through.
// AUTH PLAIN is sent only if the config has a user + password set.
func (m *SMTPMailer) Send(ctx context.Context, msg Message) error {
	if msg.To == "" {
		return errors.New("smtp: message to required")
	}
	addr := net.JoinHostPort(m.cfg.Host, fmt.Sprintf("%d", m.cfg.Port))

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp new client: %w", err)
	}
	defer c.Close()

	// STARTTLS for any reasonably-secure port. Mailhog and other dev sinks
	// listen on 1025 plain, so we skip there.
	if m.cfg.Port != 1025 {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: m.cfg.Host}); err != nil {
				return fmt.Errorf("smtp starttls: %w", err)
			}
		}
	}

	// Auth only when we have credentials. mailhog needs no auth.
	if m.cfg.User != "" && m.cfg.Password != "" {
		auth := smtp.PlainAuth("", m.cfg.User, m.cfg.Password, m.cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err := c.Mail(extractAddress(m.cfg.From)); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	if err := c.Rcpt(extractAddress(msg.To)); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}

	body, err := buildMIME(m.cfg.From, msg)
	if err != nil {
		return err
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data open: %w", err)
	}
	if _, err := wc.Write([]byte(body)); err != nil {
		_ = wc.Close()
		return fmt.Errorf("smtp data write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp data close: %w", err)
	}
	return c.Quit()
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
