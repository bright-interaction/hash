// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Tests in this file exercise the HTTP layer without requiring a Postgres or
// MinIO connection. Routes that reach the DB return 500 against a nil pool;
// we only assert the routing + middleware behavior.

func TestSecurityHeaders(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	h := (&Server{CSPScriptSrc: " 'sha256-deadbeef'"}).securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(rr, req)

	wants := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
	}
	for k, v := range wants {
		if got := rr.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP missing frame-ancestors 'none': %q", csp)
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP missing default-src 'self': %q", csp)
	}
	// The SvelteKit inline bootstrap hash must reach script-src, or the SPA renders
	// blank under the strict CSP (regression guard).
	if !strings.Contains(csp, "script-src 'self' 'sha256-deadbeef'") {
		t.Errorf("CSP script-src missing the configured inline-script hash: %q", csp)
	}
}

func TestHealthPublishesDeploymentIdentity(t *testing.T) {
	// pgxpool.New does not connect. A cancelled request makes Ping return
	// immediately, letting this exercise the real health handler without an
	// external database while still proving the headers survive a 503 response.
	pool, err := pgxpool.New(context.Background(), "postgres://hash:unused@127.0.0.1:1/hash?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/health", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	(&Server{
		Pool:        pool,
		Release:     "0123456789abcdef0123456789abcdef01234567",
		Environment: "production",
	}).handleHealth(rr, req)

	if got := rr.Header().Get("X-Hash-Release"); got != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("X-Hash-Release = %q", got)
	}
	if got := rr.Header().Get("X-Hash-Environment"); got != "production" {
		t.Errorf("X-Hash-Environment = %q", got)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
}

func TestSecurityHeadersDisableSignerCredentialCaching(t *testing.T) {
	h := (&Server{}).securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, path := range []string{"/sign/secret/document", "/a/cr?token=secret", "/e/o/secret"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if got := rr.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s Cache-Control = %q, want no-store", path, got)
		}
		if got := rr.Header().Get("Pragma"); got != "no-cache" {
			t.Errorf("%s Pragma = %q, want no-cache", path, got)
		}
	}
}

func TestSafeAccessPathRedactsURLCredentials(t *testing.T) {
	tests := map[string]string{
		"/sign/signer-secret/document":           "/sign/:token/document",
		"/e/o/open-beacon-secret":                "/e/o/:token",
		"/webhooks/billing/provider-path-secret": "/webhooks/billing/:secret",
		"/qes/callback/provider-session-secret":  "/qes/callback/:provider_session_id",
		"/health":                                "/health",
	}
	for input, want := range tests {
		if got := safeAccessPath(input); got != want {
			t.Errorf("safeAccessPath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestClientIPPreservesIPv4AndIPv6(t *testing.T) {
	tests := map[string]string{
		"192.0.2.10:443":       "192.0.2.10",
		"[2001:db8::10]:443":   "2001:db8::10",
		"2001:db8::20":         "2001:db8::20",
		"malformed-peer-value": "malformed-peer-value",
	}
	for remote, want := range tests {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if got := clientIP(r); got != want {
			t.Errorf("clientIP(%q) = %q, want %q", remote, got, want)
		}
	}
}

func TestParseAuthenticatedClientIPRequiresOneLiteralAddress(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
		ok     bool
	}{
		{name: "public IPv4", values: []string{"203.0.113.9"}, want: "203.0.113.9", ok: true},
		{name: "private VPN IPv4", values: []string{"10.23.4.5"}, want: "10.23.4.5", ok: true},
		{name: "IPv6", values: []string{"2001:db8::9"}, want: "2001:db8::9", ok: true},
		{name: "missing"},
		{name: "duplicate", values: []string{"203.0.113.9", "203.0.113.10"}},
		{name: "forwarded chain", values: []string{"198.51.100.2, 203.0.113.9"}},
		{name: "surrounding whitespace", values: []string{" 203.0.113.9"}},
		{name: "host and port", values: []string{"203.0.113.9:443"}},
		{name: "malformed", values: []string{"not-an-address"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := parseAuthenticatedClientIP(test.values)
			if got != test.want || ok != test.ok {
				t.Fatalf("parseAuthenticatedClientIP() = %q/%v, want %q/%v", got, ok, test.want, test.ok)
			}
		})
	}
}

func TestProductionProxyAuthRequiresAuthenticatedSingleClientIP(t *testing.T) {
	secret := strings.Repeat("cd", 32)
	tests := []struct {
		name        string
		peer        string
		path        string
		authHeaders []string
		clientIPs   []string
		wantStatus  int
		wantClient  string
		wantCalled  bool
	}{
		{
			name:        "managed proxy authenticates public client address",
			peer:        "172.18.0.5:43210",
			path:        "/sign/token",
			authHeaders: []string{secret},
			clientIPs:   []string{"203.0.113.9"},
			wantStatus:  http.StatusNoContent,
			wantClient:  "203.0.113.9",
			wantCalled:  true,
		},
		{
			name:        "private VPN client is not replaced by forged public XFF",
			peer:        "172.18.0.5:43210",
			path:        "/sign/token",
			authHeaders: []string{secret},
			clientIPs:   []string{"10.23.4.5"},
			wantStatus:  http.StatusNoContent,
			wantClient:  "10.23.4.5",
			wantCalled:  true,
		},
		{
			name:        "co-tenant via Caddy stays attributed to co-tenant",
			peer:        "172.18.0.5:43210",
			path:        "/sign/token",
			authHeaders: []string{secret},
			clientIPs:   []string{"10.0.6.23"},
			wantStatus:  http.StatusNoContent,
			wantClient:  "10.0.6.23",
			wantCalled:  true,
		},
		{name: "missing secret is forbidden", peer: "172.18.0.6:43210", path: "/sign/token", clientIPs: []string{"203.0.113.9"}, wantStatus: http.StatusForbidden},
		{name: "wrong secret is forbidden", peer: "172.18.0.6:43210", path: "/sign/token", authHeaders: []string{strings.Repeat("ef", 32)}, clientIPs: []string{"203.0.113.9"}, wantStatus: http.StatusForbidden},
		{name: "duplicate secret field lines are forbidden", peer: "172.18.0.6:43210", path: "/sign/token", authHeaders: []string{secret, secret}, clientIPs: []string{"203.0.113.9"}, wantStatus: http.StatusForbidden},
		{name: "missing authenticated client address is forbidden", peer: "172.18.0.6:43210", path: "/sign/token", authHeaders: []string{secret}, wantStatus: http.StatusForbidden},
		{name: "duplicate authenticated client address is forbidden", peer: "172.18.0.6:43210", path: "/sign/token", authHeaders: []string{secret}, clientIPs: []string{"203.0.113.9", "10.0.0.2"}, wantStatus: http.StatusForbidden},
		{name: "forwarded chain in authenticated address is forbidden", peer: "172.18.0.6:43210", path: "/sign/token", authHeaders: []string{secret}, clientIPs: []string{"198.51.100.2, 203.0.113.9"}, wantStatus: http.StatusForbidden},
		{name: "loopback exact health needs no headers", peer: "127.0.0.1:43210", path: "/health", wantStatus: http.StatusNoContent, wantClient: "127.0.0.1", wantCalled: true},
		{name: "loopback application route still needs headers", peer: "127.0.0.1:43210", path: "/api/v1/me", wantStatus: http.StatusForbidden},
		{name: "non-loopback health still needs headers", peer: "172.18.0.6:43210", path: "/health", wantStatus: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			gotClient := ""
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				gotClient = clientIP(r)
				if r.Header.Get(hashProxyAuthHeader) != "" || r.Header.Get(hashProxyClientIPHeader) != "" {
					t.Fatalf("proxy authentication channel reached handler")
				}
				for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Real-IP", "True-Client-IP"} {
					if r.Header.Get(name) != "" {
						t.Fatalf("unauthenticated forwarding header %s reached handler", name)
					}
				}
				w.WriteHeader(http.StatusNoContent)
			})
			h := (&Server{Environment: "production", ProxyAuth: secret}).requireProductionProxyAuth(next)
			req := httptest.NewRequest(http.MethodGet, test.path, nil)
			req.RemoteAddr = test.peer
			// Model a forged public left entry followed by the private address nginx
			// actually observed. It must never override Caddy's dedicated value.
			req.Header.Set("Forwarded", `for=198.51.100.99`)
			req.Header.Set("X-Forwarded-For", "198.51.100.99, 192.168.1.44")
			req.Header.Set("X-Real-IP", "198.51.100.99")
			req.Header.Set("True-Client-IP", "198.51.100.99")
			for _, value := range test.authHeaders {
				req.Header.Add(hashProxyAuthHeader, value)
			}
			for _, value := range test.clientIPs {
				req.Header.Add(hashProxyClientIPHeader, value)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != test.wantStatus || called != test.wantCalled {
				t.Fatalf("status/called = %d/%v, want %d/%v", rr.Code, called, test.wantStatus, test.wantCalled)
			}
			if gotClient != test.wantClient {
				t.Fatalf("client IP = %q, want %q", gotClient, test.wantClient)
			}
			if req.Header.Get(hashProxyAuthHeader) != "" || req.Header.Get(hashProxyClientIPHeader) != "" {
				t.Fatal("proxy authentication channel was not stripped")
			}
		})
	}
}

func TestNonProductionProxyAuthIsDisabledButHeaderIsStripped(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		if r.Header.Get(hashProxyAuthHeader) != "" || r.Header.Get(hashProxyClientIPHeader) != "" {
			t.Fatal("proxy authentication channel reached development handler")
		}
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set(hashProxyAuthHeader, "client-supplied")
	req.Header.Set(hashProxyClientIPHeader, "203.0.113.9")
	(&Server{Environment: "development"}).requireProductionProxyAuth(next).ServeHTTP(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("development request was unexpectedly gated")
	}
}

func TestLooksLikePDF(t *testing.T) {
	if !looksLikePDF([]byte("%PDF-1.7\n...rest")) {
		t.Error("real PDF magic bytes rejected")
	}
	if looksLikePDF([]byte("not a pdf")) {
		t.Error("non-PDF accepted")
	}
	if looksLikePDF([]byte("")) {
		t.Error("empty accepted")
	}
	if looksLikePDF([]byte("%PD")) {
		t.Error("truncated accepted")
	}
}

func TestPaginationFromQuery(t *testing.T) {
	cases := []struct {
		name             string
		url              string
		defLimit, maxLim int32
		wantLimit        int32
		wantOffset       int32
	}{
		{"defaults", "/x", 50, 500, 50, 0},
		{"explicit", "/x?limit=20&offset=5", 50, 500, 20, 5},
		{"capped", "/x?limit=9999", 50, 500, 500, 0},
		{"negative offset ignored", "/x?offset=-1", 50, 500, 50, 0},
		{"non-int limit ignored", "/x?limit=abc", 50, 500, 50, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			limit, offset := paginationFromQuery(req, tc.defLimit, tc.maxLim)
			if limit != tc.wantLimit || offset != tc.wantOffset {
				t.Errorf("got (%d,%d), want (%d,%d)", limit, offset, tc.wantLimit, tc.wantOffset)
			}
		})
	}
}

func TestUnauthenticatedRoutesReject(t *testing.T) {
	// Build a router with no DB; auth middleware should reject before any
	// handler runs.
	srv := &Server{}
	r := srv.Routes()

	cases := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/me"},
		{http.MethodGet, "/api/v1/templates"},
		{http.MethodPost, "/api/v1/templates"},
		{http.MethodGet, "/api/v1/documents"},
		{http.MethodPost, "/api/v1/documents"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: got %d, want 401", tc.method, tc.path, rr.Code)
		}
	}
}

func TestNullableString(t *testing.T) {
	if v := nullableString(""); v != nil {
		t.Errorf("empty string should be nil, got %v", v)
	}
	if v := nullableString("hi"); v != "hi" {
		t.Errorf(`non-empty should pass through, got %v`, v)
	}
}
