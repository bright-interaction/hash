// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// main.go tolerates a failed OIDC init by setting s.OIDC = nil so the server
// still boots without an IdP, and production hash runs exactly that way (no
// OIDC_* variables set). Both auth routes are public and unauthenticated, so
// before this guard a bare `curl /auth/login` dereferenced the nil OIDC and
// panicked: a 500 for the caller and a FATAL crash report in Flare, reachable
// by anyone including a bot sweeping common auth paths.
//
// t.Run subtests rather than a shared server: a panic must fail the case it
// happened in, not abort the whole file.
func TestAuthRoutesDoNotPanicWithoutOIDC(t *testing.T) {
	tests := []struct {
		name   string
		method string
		target string
		handle func(*Server, http.ResponseWriter, *http.Request)
	}{
		{"login", http.MethodGet, "/auth/login", (*Server).handleAuthLogin},
		{"callback", http.MethodGet, "/auth/callback?code=x&state=y", (*Server).handleAuthCallback},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{} // OIDC nil, exactly as a failed init leaves it
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.target, nil)

			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("%s panicked with a nil OIDC: %v", tt.target, p)
				}
			}()
			tt.handle(s, rec, req)

			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("%s status: got %d, want %d", tt.target, rec.Code, http.StatusServiceUnavailable)
			}
		})
	}
}
