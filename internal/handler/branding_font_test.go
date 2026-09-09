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

func TestOrgBrandingRESTRejectsWhitespaceFontBeforeDatabaseMutation(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.OrgIDKey, uuid.New())
	req := httptest.NewRequest(http.MethodPut, "/api/v1/branding",
		strings.NewReader(`{"font_body":" \t\n "}`)).WithContext(ctx)
	recorder := httptest.NewRecorder()

	// Pool is intentionally nil: malformed input must fail before the mutation
	// boundary is reachable.
	(&Server{}).handleUpsertOrgBranding(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("whitespace font status = %d, want 400; body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "font_body") {
		t.Fatalf("whitespace font response did not identify field: %s", recorder.Body.String())
	}
}
