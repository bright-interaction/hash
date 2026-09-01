// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package flarereport

import (
	"strings"
	"testing"

	sentry "github.com/getsentry/sentry-go"
)

func TestRedactCredentialPath(t *testing.T) {
	secrets := []string{"signerSecret", "beaconSecret", "billingSecret", "providerSession"}
	raw := "https://hash.example/sign/" + secrets[0] + "/document/" +
		"e/o/" + secrets[1] + "/webhooks/billing/" + secrets[2] +
		"/qes/callback/" + secrets[3]
	got := redactCredentialPath(raw)
	for _, secret := range secrets {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted path still contains %q: %s", secret, got)
		}
	}
}

func TestNormalizeTracePathAlwaysRedactsCredentialSegments(t *testing.T) {
	for _, path := range []string{
		"/sign/lettersOnlyToken/document",
		"/e/o/lettersOnlyBeacon",
		"/webhooks/billing/lettersOnlySecret",
		"/qes/callback/lettersOnlySession",
	} {
		if got := normalizeTracePath(path); strings.Contains(got, "lettersOnly") {
			t.Fatalf("normalizeTracePath(%q) leaked credential: %q", path, got)
		}
	}
}

func TestScrubSensitiveDropsRequestPIIAndCredentials(t *testing.T) {
	event := &sentry.Event{Request: &sentry.Request{
		URL:         "https://hash.example/sign/ceremony-secret/document",
		Method:      "POST",
		Data:        `{"typed_name":"Sensitive Person","comment":"private"}`,
		QueryString: "t=one-click-secret",
		Cookies:     "hash_session=session-secret",
		Headers: map[string]string{
			"Authorization":   "Bearer api-secret",
			"X-Forwarded-For": "203.0.113.10",
		},
		Env: map[string]string{"REMOTE_ADDR": "203.0.113.10"},
	}}

	got := scrubSensitive(event, nil)
	if got == nil || got.Request == nil {
		t.Fatal("scrubber removed the event/request entirely")
	}
	if got.Request.Method != "POST" || !strings.Contains(got.Request.URL, "/sign/[redacted]/document") {
		t.Fatalf("scrubbed route identity = %#v", got.Request)
	}
	if got.Request.Data != "" || got.Request.QueryString != "" || got.Request.Cookies != "" ||
		got.Request.Headers != nil || got.Request.Env != nil {
		t.Fatalf("request PII survived scrub: %#v", got.Request)
	}
}
