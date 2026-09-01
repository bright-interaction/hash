// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireSameOriginMutation(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		host         string
		origin       string
		fetchSite    string
		wantStatus   int
		wantNextCall bool
	}{
		{name: "safe read permits foreign origin", method: http.MethodGet, origin: "https://evil.example", wantStatus: http.StatusNoContent, wantNextCall: true},
		{name: "configured public origin", method: http.MethodPost, host: "hash.internal:8080", origin: "https://hash.example.com", wantStatus: http.StatusNoContent, wantNextCall: true},
		{name: "public alias matching request host", method: http.MethodPatch, host: "esign.example.com", origin: "https://esign.example.com", wantStatus: http.StatusNoContent, wantNextCall: true},
		{name: "scheme downgrade refused", method: http.MethodPost, host: "hash.example.com", origin: "http://hash.example.com", wantStatus: http.StatusForbidden},
		{name: "sibling origin refused", method: http.MethodPost, host: "hash.example.com", origin: "https://crm.example.com", fetchSite: "same-site", wantStatus: http.StatusForbidden},
		{name: "foreign origin refused", method: http.MethodDelete, host: "hash.example.com", origin: "https://evil.example", fetchSite: "cross-site", wantStatus: http.StatusForbidden},
		{name: "opaque origin refused", method: http.MethodPost, host: "hash.example.com", origin: "null", wantStatus: http.StatusForbidden},
		{name: "origin with path refused", method: http.MethodPost, host: "hash.example.com", origin: "https://hash.example.com/path", wantStatus: http.StatusForbidden},
		{name: "missing origin but sibling metadata refused", method: http.MethodPost, host: "hash.example.com", fetchSite: "same-site", wantStatus: http.StatusForbidden},
		{name: "same-origin metadata accepted", method: http.MethodPut, host: "hash.example.com", fetchSite: "same-origin", wantStatus: http.StatusNoContent, wantNextCall: true},
		{name: "trusted non-browser request accepted", method: http.MethodPost, host: "hash.example.com", wantStatus: http.StatusNoContent, wantNextCall: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextCalled := false
			s := &Server{PublicURL: "https://hash.example.com"}
			h := s.requireSameOriginMutation(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequest(tt.method, "https://hash.example.com/api/v1/documents", nil)
			if tt.host != "" {
				req.Host = tt.host
			}
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.fetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tt.fetchSite)
			}
			res := httptest.NewRecorder()
			h.ServeHTTP(res, req)
			if res.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", res.Code, tt.wantStatus)
			}
			if nextCalled != tt.wantNextCall {
				t.Fatalf("next called = %v, want %v", nextCalled, tt.wantNextCall)
			}
		})
	}
}

func TestAllowedMutationOriginRejectsCredentialedURL(t *testing.T) {
	if allowedMutationOrigin("https://hash.example.com@evil.example", "hash.example.com", "https://hash.example.com") {
		t.Fatal("userinfo URL must not be accepted as the configured origin")
	}
}

func TestSessionRouteWiresSameOriginGuardBeforeAuthentication(t *testing.T) {
	s := &Server{PublicURL: "https://hash.example.com"}
	req := httptest.NewRequest(http.MethodPost, "https://hash.example.com/api/v1/documents", nil)
	req.Host = "hash.example.com"
	req.Header.Set("Origin", "https://sibling.example.com")
	res := httptest.NewRecorder()
	s.Routes().ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("foreign mutation status = %d, want %d", res.Code, http.StatusForbidden)
	}
}

func TestLogoutRouteWiresSameOriginGuard(t *testing.T) {
	s := &Server{PublicURL: "https://hash.example.com"}
	req := httptest.NewRequest(http.MethodPost, "https://hash.example.com/auth/logout", nil)
	req.Host = "hash.example.com"
	req.Header.Set("Origin", "https://crm.example.com")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	res := httptest.NewRecorder()
	s.Routes().ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("sibling-origin logout status = %d, want %d", res.Code, http.StatusForbidden)
	}
}
