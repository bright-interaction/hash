// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/auth"
)

func TestProductionRefusesUnapprovedBuiltInLegalStarter(t *testing.T) {
	ctx := context.WithValue(context.Background(), auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.OrgIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	ctx = context.WithValue(ctx, auth.EmailKey, "owner@example.invalid")

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/templates/starter",
		strings.NewReader(`{"key":"services-agreement-sv"}`),
	).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	(&Server{Environment: "production"}).handleCreateStarterTemplate(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("production starter status = %d, want %d; body=%s", rr.Code, http.StatusServiceUnavailable, rr.Body.String())
	}
}
