package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIKeyEndpoints_RejectUnauthenticated(t *testing.T) {
	srv := &Server{}
	r := srv.Routes()

	cases := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/api-keys"},
		{http.MethodPost, "/api/v1/api-keys"},
		{http.MethodDelete, "/api/v1/api-keys/00000000-0000-0000-0000-000000000000"},
		{http.MethodGet, "/api/v1/webhooks"},
		{http.MethodPost, "/api/v1/webhooks"},
		{http.MethodDelete, "/api/v1/webhooks/00000000-0000-0000-0000-000000000000"},
		{http.MethodGet, "/api/v1/dashboard"},
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

func TestSecurityHeadersOnNewRoutes(t *testing.T) {
	srv := &Server{}
	r := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if !strings.Contains(rr.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("CSP missing on new endpoint: %q", rr.Header().Get("Content-Security-Policy"))
	}
}
