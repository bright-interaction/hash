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

func TestProductionRefusesUnapprovedComplianceLegalKit(t *testing.T) {
	ctx := context.WithValue(context.Background(), auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.OrgIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	ctx = context.WithValue(ctx, auth.EmailKey, "owner@example.invalid")

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/compliance/seed",
		strings.NewReader(`{"business_type":"saas","jurisdiction":"SE"}`),
	).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	(&Server{Environment: "production"}).handleSeedCompliance(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("production compliance seed status = %d, want %d; body=%s", rr.Code, http.StatusServiceUnavailable, rr.Body.String())
	}
}
