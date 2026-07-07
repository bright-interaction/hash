package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
		"Referrer-Policy":           "strict-origin-when-cross-origin",
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
