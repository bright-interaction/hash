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

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/auth"
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

func TestCreateAPIKeyValidationDoesNotDependOnMCPBilling(t *testing.T) {
	// Billing is deliberately nil. When API-key issuance was incorrectly gated
	// on MCP this request returned 503 before ordinary request validation. The
	// standalone automation API is core, so its credential can be prepared even
	// when no MCP entitlement engine is configured.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", strings.NewReader(`{"name":"","scopes":["write:authoring","write:workflow"]}`))
	ctx := context.WithValue(req.Context(), auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.OrgIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	ctx = context.WithValue(ctx, auth.EmailKey, "owner@example.test")
	res := httptest.NewRecorder()
	(&Server{}).handleCreateAPIKey(res, req.WithContext(ctx))
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "name required") {
		t.Fatalf("issuance validation status/body = %d/%s, want plan-independent 400", res.Code, res.Body.String())
	}
}
