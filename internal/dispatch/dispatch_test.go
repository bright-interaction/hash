// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsPublicEventKind(t *testing.T) {
	publics := []string{
		"document.created", "document.sent", "document.signed",
		"document.completed", "document.declined", "document.voided",
		"document.expired", "document.viewed", "document.opened",
		"document.field_filled", "recipient.invited", "recipient.bounced",
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

// ── Templates ────────────────────────────────────────────────────────────

func TestRender_AllKinds(t *testing.T) {
	ctx := TemplateContext{
		DocumentName:  "Acme NDA",
		SenderName:    "Tom",
		SenderEmail:   "tom@bright.example",
		RecipientName: "Bob",
		OrgName:       "Bright Interaction",
		SignURL:       "https://esign.brightinteraction.com/sign/abc",
		BeaconURL:     "https://esign.brightinteraction.com/e/o/abc",
		DownloadURL:   "https://esign.brightinteraction.com/download/abc",
		DeclineReason: "out of scope",
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

func TestRender_BeaconOptional(t *testing.T) {
	// Without BeaconURL, no <img> tag should appear.
	_, html, _, err := Render(KindInvite, TemplateContext{
		DocumentName: "Doc", SenderName: "S", OrgName: "Org",
		SignURL: "https://x", BeaconURL: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, "<img") {
		t.Errorf("beacon img should be absent when BeaconURL=\"\": %s", html)
	}
	// With BeaconURL it should be present.
	_, htmlWith, _, _ := Render(KindInvite, TemplateContext{
		DocumentName: "Doc", SenderName: "S", OrgName: "Org",
		SignURL: "https://x", BeaconURL: "https://x/beacon",
	})
	if !strings.Contains(htmlWith, `src="https://x/beacon"`) {
		t.Errorf("beacon img missing: %s", htmlWith)
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

// ── Webhook signing + verify ─────────────────────────────────────────────

func TestSignVerify_RoundTrip(t *testing.T) {
	body := []byte(`{"event_id":"abc","kind":"document.signed"}`)
	sig := Sign("super-secret", body, time.Unix(1700000000, 0))
	if !Verify(SignaturePair{Primary: "super-secret"}, body, sig) {
		t.Error("round-trip verify failed")
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
