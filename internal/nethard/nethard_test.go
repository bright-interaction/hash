// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package nethard

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCredentialedClientDoesNotFollowRedirects(t *testing.T) {
	var redirected atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Store(true)
	}))
	t.Cleanup(destination.Close)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)

	req, err := http.NewRequest(http.MethodPost, source.URL, strings.NewReader("sensitive prompt"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	_, err = Client(time.Second, func() bool { return true }).Do(req)
	if err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("credentialed redirect should fail closed, got %v", err)
	}
	if redirected.Load() {
		t.Fatal("redirect destination received the credentialed request")
	}
}

func TestIsBlockedIP(t *testing.T) {
	for _, s := range []string{
		"127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1",
		"172.16.0.1", "0.0.0.0", "::1", "100.64.0.1",
		"100.127.255.254", "::ffff:100.100.100.100", "198.18.0.1",
	} {
		if !IsBlockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34"} {
		if IsBlockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
	if !IsBlockedIP(nil) {
		t.Error("nil IP should be blocked")
	}
}

func TestTransportRefusesInternalDial(t *testing.T) {
	c := Client(2*time.Second, func() bool { return false })
	// Cloud-metadata IP must be refused at dial time (the SSRF-rebinding close).
	_, err := c.Get("http://169.254.169.254/latest/meta-data/")
	if err == nil {
		t.Fatal("expected dial to internal IP to be refused")
	}
	if !strings.Contains(err.Error(), "internal address") {
		t.Errorf("expected nethard refusal, got: %v", err)
	}
}

func TestTransportAllowsWhenAllowPrivate(t *testing.T) {
	// allowPrivate=true (local dev) must NOT reject a private dial at the Control
	// hook; the connection then fails for an unrelated reason (nothing listening),
	// which is fine - we only assert the refusal message is absent.
	c := Client(1*time.Second, func() bool { return true })
	_, err := c.Get("http://127.0.0.1:0/")
	if err != nil && strings.Contains(err.Error(), "internal address") {
		t.Errorf("allowPrivate should not trip the guard: %v", err)
	}
}
