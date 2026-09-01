// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestIsPublicEventKind(t *testing.T) {
	publics := []string{
		"document.created", "document.sent", "document.signed",
		"document.completed", "document.declined", "document.changes_requested", "document.voided",
		"document.expired", "document.viewed", "document.opened",
		"document.field_filled", "recipient.created", "recipient.invited", "recipient.bounced",
	}
	for _, k := range publics {
		if !IsPublicEventKind(k) {
			t.Errorf("%s should be public", k)
		}
	}
	internals := []string{
		"webhook.dispatched", "webhook.failed", "clarifier.answered",
		"risk.analyzed", "billing.checkout_started", "qes.session_completed",
		"collab.peer_joined", "negotiation.proposed",
	}
	for _, k := range internals {
		if IsPublicEventKind(k) {
			t.Errorf("%s should be internal-only", k)
		}
	}
}

func TestValidateWebhookURLRejectsSharedAddressSpace(t *testing.T) {
	for _, raw := range []string{
		"https://100.64.0.1/hook",
		"https://100.127.255.254/hook",
		"https://198.18.0.1/hook",
	} {
		if err := ValidateWebhookURL(raw, false); err == nil {
			t.Errorf("%s should be rejected", raw)
		}
	}
}

// ── Templates ────────────────────────────────────────────────────────────

func TestRender_AllKinds(t *testing.T) {
	ctx := TemplateContext{
		DocumentName:      "Acme NDA",
		SenderName:        "Tom",
		SenderEmail:       "tom@bright.example",
		RecipientName:     "Bob",
		OrgName:           "Bright Interaction",
		SignURL:           "https://esign.brightinteraction.com/sign/abc",
		BeaconURL:         "https://esign.brightinteraction.com/e/o/abc",
		DownloadURL:       "https://esign.brightinteraction.com/download/abc",
		DownloadExpiresAt: "2026-08-31T12:00:00Z",
		DeclineReason:     "out of scope",
	}
	for _, kind := range []string{
		KindInvite, KindReminder,
		KindCompletedSigner, KindCompletedSender,
		KindDeclined, KindVoided,
	} {
		t.Run(kind, func(t *testing.T) {
			subj, htmlBody, textBody, err := Render(kind, ctx)
			if err != nil {
				t.Fatalf("render %s: %v", kind, err)
			}
			if subj == "" {
				t.Errorf("subject empty for %s", kind)
			}
			if !strings.Contains(htmlBody, "Acme NDA") && !strings.Contains(htmlBody, "Bob") {
				t.Errorf("html missing context fields: %s", htmlBody)
			}
			if textBody == "" {
				t.Errorf("text body empty for %s", kind)
			}
		})
	}
}

func TestRender_UnknownKind(t *testing.T) {
	if _, _, _, err := Render("email.bogus", TemplateContext{}); err == nil {
		t.Fatal("expected error for unknown kind")
	}
}

func TestRender_InviteIncludesSignURL(t *testing.T) {
	_, html, text, err := Render(KindInvite, TemplateContext{
		DocumentName: "Doc", SenderName: "S", OrgName: "Org",
		SignURL: "https://example.com/sign/xyz",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, "https://example.com/sign/xyz") {
		t.Errorf("html missing sign URL: %s", html)
	}
	if !strings.Contains(text, "https://example.com/sign/xyz") {
		t.Errorf("text missing sign URL: %s", text)
	}
}

func TestRender_InviteAndReminderMatchCeremonyMode(t *testing.T) {
	for _, kind := range []string{KindInvite, KindReminder} {
		t.Run(kind+"_acknowledgement", func(t *testing.T) {
			subject, htmlBody, textBody, err := Render(kind, TemplateContext{
				DocumentName: "Policy", SenderName: "Sender", SenderEmail: "sender@example.test",
				RecipientName: "Recipient", OrgName: "Org", Locale: "sv",
				SignURL: "https://example.test/sign/token", Acknowledgement: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			rendered := strings.ToLower(subject + "\n" + htmlBody + "\n" + textBody)
			for _, want := range []string{"acknowledg", "no signature will be requested"} {
				if !strings.Contains(rendered, want) {
					t.Fatalf("acknowledgement %s missing %q: %s", kind, want, rendered)
				}
			}
			for _, forbidden := range []string{"for signature", "review and sign", "awaiting your signature", "open and sign"} {
				if strings.Contains(rendered, forbidden) {
					t.Fatalf("acknowledgement %s contains signing instruction %q: %s", kind, forbidden, rendered)
				}
			}
		})

		t.Run(kind+"_signature", func(t *testing.T) {
			subject, htmlBody, textBody, err := Render(kind, TemplateContext{
				DocumentName: "Agreement", SenderName: "Sender", SenderEmail: "sender@example.test",
				RecipientName: "Recipient", OrgName: "Org", Locale: "en",
				SignURL: "https://example.test/sign/token",
			})
			if err != nil {
				t.Fatal(err)
			}
			rendered := strings.ToLower(subject + "\n" + htmlBody + "\n" + textBody)
			if !strings.Contains(rendered, "sign") || strings.Contains(rendered, "acknowledg") {
				t.Fatalf("signature %s did not retain signing-specific copy: %s", kind, rendered)
			}
		})
	}
}

func TestRender_RecipientFooterDoesNotClaimUnattestedDataSovereignty(t *testing.T) {
	for _, locale := range []string{"en", "sv", "de", "fr"} {
		for _, kind := range []string{KindInvite, KindReminder} {
			_, htmlBody, textBody, err := Render(kind, TemplateContext{
				DocumentName: "Doc",
				SenderName:   "Sender",
				OrgName:      "Org",
				Locale:       locale,
				SignURL:      "https://example.test/sign/token",
			})
			if err != nil {
				t.Fatalf("render %s/%s: %v", locale, kind, err)
			}
			for _, rendered := range []string{htmlBody, textBody} {
				lower := strings.ToLower(rendered)
				for _, forbidden := range []string{"eu-sovereign", "eu-suver", "eu-souver"} {
					if strings.Contains(lower, forbidden) {
						t.Fatalf("%s/%s footer contains unverified sovereignty claim %q", locale, kind, forbidden)
					}
				}
			}
		}
	}
}

func TestInviteAndReminderNeverRenderPreNoticeTrackingPixels(t *testing.T) {
	for _, kind := range []string{KindInvite, KindReminder} {
		_, htmlBody, _, err := Render(kind, TemplateContext{
			DocumentName: "Doc", SenderName: "S", OrgName: "Org",
			SignURL: "https://x/sign/token", BeaconURL: "https://x/e/o/token",
		})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(htmlBody, "<img") || strings.Contains(htmlBody, "/e/o/") {
			t.Fatalf("%s rendered recipient-identifiable pre-notice tracking: %s", kind, htmlBody)
		}
	}
}

// ── SMTP MIME builder ────────────────────────────────────────────────────

func TestBuildMIME_HasBothParts(t *testing.T) {
	body, err := buildMIME("from@example.com", Message{
		To:      "to@example.com",
		Subject: "test",
		HTML:    "<p>hi</p>",
		Text:    "hi",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"From: from@example.com",
		"To: to@example.com",
		"Subject: test",
		"multipart/alternative",
		"text/plain",
		"text/html",
		"<p>hi</p>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("MIME missing %q: %s", want, body)
		}
	}
}

func TestBuildMIME_AutoStripsToText(t *testing.T) {
	body, err := buildMIME("from@example.com", Message{
		To:      "to@example.com",
		Subject: "subj",
		HTML:    "<p>Hello <strong>world</strong></p>",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "Hello world") {
		t.Errorf("plaintext fallback should be derived from HTML: %s", body)
	}
}

func TestExtractAddress(t *testing.T) {
	cases := map[string]string{
		"tom@x.com":           "tom@x.com",
		"Tom <tom@x.com>":     "tom@x.com",
		"  Tom <tom@x.com>  ": "tom@x.com",
		"<tom@x.com>":         "tom@x.com",
	}
	for in, want := range cases {
		if got := extractAddress(in); got != want {
			t.Errorf("extractAddress(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewSMTPMailerRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name string
		cfg  SMTPConfig
	}{
		{name: "missing host", cfg: SMTPConfig{From: "Hash <hash@example.test>"}},
		{name: "missing from", cfg: SMTPConfig{Host: "smtp.example.test"}},
		{name: "invalid from", cfg: SMTPConfig{Host: "smtp.example.test", From: "not an address"}},
		{name: "port too high", cfg: SMTPConfig{Host: "smtp.example.test", Port: 65536, From: "hash@example.test"}},
		{name: "user without password", cfg: SMTPConfig{Host: "smtp.example.test", User: "hash", From: "hash@example.test"}},
		{name: "password without user", cfg: SMTPConfig{Host: "smtp.example.test", Password: "secret", From: "hash@example.test"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewSMTPMailer(tt.cfg); err == nil {
				t.Fatal("expected invalid SMTP configuration to be rejected")
			}
		})
	}
}

func TestSMTPMailerRequiresSTARTTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		if _, writeErr := rw.WriteString("220 smtp.example.test ESMTP\r\n"); writeErr != nil {
			serverDone <- writeErr
			return
		}
		if flushErr := rw.Flush(); flushErr != nil {
			serverDone <- flushErr
			return
		}
		if _, readErr := rw.ReadString('\n'); readErr != nil {
			serverDone <- readErr
			return
		}
		if _, writeErr := rw.WriteString("250-smtp.example.test\r\n250 AUTH PLAIN\r\n"); writeErr != nil {
			serverDone <- writeErr
			return
		}
		serverDone <- rw.Flush()
	}()

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	mailer, err := NewSMTPMailer(SMTPConfig{
		Host: host,
		Port: port,
		From: "Hash <hash@example.test>",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = mailer.Send(context.Background(), Message{
		To: "signer@example.test", Subject: "Sign", Text: "Please sign",
	})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS is required") {
		t.Fatalf("server without STARTTLS must fail closed, got %v", err)
	}
	if serverErr := <-serverDone; serverErr != nil {
		t.Fatalf("fake SMTP server: %v", serverErr)
	}
}

func TestSMTPMailerGreetingStallHonorsContextDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer conn.Close()
		// Deliberately never send the SMTP greeting. Reading one byte proves the
		// client closed the accepted socket when its context expired.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var one [1]byte
		_, readErr := conn.Read(one[:])
		if readErr == nil {
			serverDone <- errors.New("client wrote data before the SMTP greeting")
			return
		}
		serverDone <- nil
	}()

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	mailer, err := NewSMTPMailer(SMTPConfig{
		Host: host,
		Port: port,
		From: "Hash <hash@example.test>",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = mailer.Send(ctx, Message{
		To: "signer@example.test", Subject: "Sign", Text: "Please sign",
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("greeting stall error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("greeting stall took %s; context cancellation did not close the connection promptly", elapsed)
	}
	if serverErr := <-serverDone; serverErr != nil {
		t.Fatalf("fake stalled SMTP server: %v", serverErr)
	}
}

func TestSMTPOperationErrorPreservesCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := smtpOperationError(ctx, "smtp data write", errors.New("connection reset"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled SMTP operation = %v, want context.Canceled", err)
	}

	providerErr := errors.New("provider rejected message")
	err = smtpOperationError(context.Background(), "smtp data close", providerErr)
	if !errors.Is(err, providerErr) {
		t.Fatalf("uncanceled SMTP operation = %v, want provider error", err)
	}
}

// ── Webhook signing + verify ─────────────────────────────────────────────

func TestSignVerify_RoundTrip(t *testing.T) {
	body := []byte(`{"event_id":"abc","kind":"document.signed"}`)
	sig := Sign("super-secret", body, time.Unix(1700000000, 0))
	if !Verify(SignaturePair{Primary: "super-secret"}, body, sig) {
		t.Error("round-trip verify failed")
	}
}

// This vector is also pinned by Reactor's hash-v1 verifier. Keeping the exact
// bytes and digest in both repositories catches a wire-contract drift before
// a Hash lifecycle callback reaches production.
func TestSign_ReactorHashV1FixedVector(t *testing.T) {
	body := []byte(`{"event_id":"evt_hash","data":{"x":1}}`)
	want := "t=1700000000,v1=959d873de800f9bb3c9b886f9172054d834cd21d7b61bb513b5bfcf97c1f43e3"
	if got := Sign("hash-secret", body, time.Unix(1700000000, 0)); got != want {
		t.Fatalf("Sign() = %q, want shared Reactor vector %q", got, want)
	}
}

func TestVerify_AcceptsPreviousSecret(t *testing.T) {
	body := []byte(`{"hi":1}`)
	sig := Sign("old-secret", body, time.Unix(1700000000, 0))
	if !Verify(SignaturePair{Primary: "new-secret", Previous: "old-secret"}, body, sig) {
		t.Error("rotation grace failed")
	}
}

func TestVerify_RejectsTamperedBody(t *testing.T) {
	body := []byte(`{"hi":1}`)
	sig := Sign("k", body, time.Unix(1700000000, 0))
	if Verify(SignaturePair{Primary: "k"}, []byte(`{"hi":2}`), sig) {
		t.Error("tampered body verified")
	}
}

func TestVerify_RejectsDifferentSecret(t *testing.T) {
	body := []byte(`{"hi":1}`)
	sig := Sign("k", body, time.Unix(1700000000, 0))
	if Verify(SignaturePair{Primary: "wrong"}, body, sig) {
		t.Error("different secret verified")
	}
}

func TestVerify_RejectsMalformedHeader(t *testing.T) {
	if Verify(SignaturePair{Primary: "k"}, []byte(`{}`), "garbage") {
		t.Error("malformed header verified")
	}
}

func TestBackoff(t *testing.T) {
	cases := []struct {
		attempts int
		want     time.Duration
		ok       bool
	}{
		{0, 1 * time.Minute, true},
		{1, 5 * time.Minute, true},
		{2, 25 * time.Minute, true},
		{3, 2 * time.Hour, true},
		{4, 12 * time.Hour, true},
		{5, 24 * time.Hour, true},
		{6, 0, false},
		{-1, 0, false},
	}
	for _, c := range cases {
		got, ok := Backoff(c.attempts)
		if got != c.want || ok != c.ok {
			t.Errorf("Backoff(%d) = (%v, %v), want (%v, %v)", c.attempts, got, ok, c.want, c.ok)
		}
	}
}

// ── End-to-end Dispatch via httptest ─────────────────────────────────────

func TestDispatcher_PostsSignedJSON(t *testing.T) {
	receivedBody := ""
	receivedSig := ""
	receivedKind := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 2048)
		n, _ := r.Body.Read(buf)
		receivedBody = string(buf[:n])
		receivedSig = r.Header.Get("X-Hash-Signature")
		receivedKind = r.Header.Get("X-Hash-Event")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewDispatcher(SignaturePair{Primary: "secret"})
	d.AllowPrivate = true // loopback test servers
	res := d.Dispatch(context.Background(), srv.URL, WebhookEvent{
		EventID: "abc", Kind: "document.signed", OccurredAt: time.Unix(1700000000, 0),
	})
	if res.Err != nil {
		t.Fatalf("dispatch error: %v", res.Err)
	}
	if res.Status != 200 {
		t.Fatalf("status = %d", res.Status)
	}
	if !strings.Contains(receivedBody, `"kind":"document.signed"`) {
		t.Errorf("body wrong: %s", receivedBody)
	}
	if receivedKind != "document.signed" {
		t.Errorf("X-Hash-Event = %q", receivedKind)
	}
	if !Verify(SignaturePair{Primary: "secret"}, []byte(receivedBody), receivedSig) {
		t.Errorf("signature failed to verify; sig=%s", receivedSig)
	}
}

func TestDispatcher_NoSecretFails(t *testing.T) {
	d := NewDispatcher(SignaturePair{})
	d.AllowPrivate = true // loopback test servers
	res := d.Dispatch(context.Background(), "http://example.com", WebhookEvent{Kind: "x"})
	if res.Err == nil {
		t.Error("expected error when no secret configured")
	}
}

func TestDispatchWithSecret_PerEndpointSigns(t *testing.T) {
	receivedBody := ""
	receivedSig := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 2048)
		n, _ := r.Body.Read(buf)
		receivedBody = string(buf[:n])
		receivedSig = r.Header.Get("X-Hash-Signature")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewDispatcher(SignaturePair{Primary: "instance-fallback"})
	d.AllowPrivate = true // loopback test servers
	res := d.DispatchWithSecret(context.Background(), srv.URL, "per-endpoint-secret-32-chars-long", WebhookEvent{
		EventID: "abc", Kind: "document.sent",
	})
	if res.Err != nil {
		t.Fatalf("dispatch error: %v", res.Err)
	}
	// Verify the signature was generated with the PER-ENDPOINT secret,
	// not the instance-wide fallback.
	if !Verify(SignaturePair{Primary: "per-endpoint-secret-32-chars-long"}, []byte(receivedBody), receivedSig) {
		t.Errorf("expected signature to verify with per-endpoint key; sig=%s", receivedSig)
	}
	if Verify(SignaturePair{Primary: "instance-fallback"}, []byte(receivedBody), receivedSig) {
		t.Error("signature should NOT verify with instance fallback when per-endpoint secret is set")
	}
}

func TestDispatchWithSecret_EmptyFallsBackToInstance(t *testing.T) {
	receivedSig := ""
	receivedBody := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 2048)
		n, _ := r.Body.Read(buf)
		receivedBody = string(buf[:n])
		receivedSig = r.Header.Get("X-Hash-Signature")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewDispatcher(SignaturePair{Primary: "legacy-instance-secret"})
	d.AllowPrivate = true // loopback test servers
	res := d.DispatchWithSecret(context.Background(), srv.URL, "", WebhookEvent{Kind: "document.viewed"})
	if res.Err != nil {
		t.Fatalf("dispatch error: %v", res.Err)
	}
	if !Verify(SignaturePair{Primary: "legacy-instance-secret"}, []byte(receivedBody), receivedSig) {
		t.Errorf("expected fallback to instance secret when per-endpoint is empty")
	}
}

func TestDispatchWithSecret_BothEmptyFails(t *testing.T) {
	d := NewDispatcher(SignaturePair{})
	d.AllowPrivate = true // loopback test servers
	res := d.DispatchWithSecret(context.Background(), "http://example.com", "", WebhookEvent{Kind: "x"})
	if res.Err == nil {
		t.Error("expected error when both per-endpoint and instance secrets empty")
	}
}

// ── Recording mailer ─────────────────────────────────────────────────────

func TestRecordingMailer(t *testing.T) {
	m := &RecordingMailer{}
	_ = m.Send(context.Background(), Message{To: "a", Subject: "1"})
	_ = m.Send(context.Background(), Message{To: "b", Subject: "2"})
	if len(m.Sent) != 2 {
		t.Fatalf("expected 2 sends, got %d", len(m.Sent))
	}
	if m.Sent[0].To != "a" || m.Sent[1].Subject != "2" {
		t.Errorf("captured wrong messages: %+v", m.Sent)
	}
}
