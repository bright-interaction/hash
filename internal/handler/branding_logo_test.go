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

func TestProductionBrandingLogoUploadFailsBeforeStorageMutation(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.OrgIDKey, uuid.New())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/branding/logo", strings.NewReader("must not be parsed")).WithContext(ctx)
	recorder := httptest.NewRecorder()

	(&Server{Environment: "production"}).handleUploadBrandingLogo(recorder, req)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("production logo upload status = %d, want %d; body=%s", recorder.Code, http.StatusConflict, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "exact version") {
		t.Fatalf("production logo upload did not explain immutable-evidence gate: %s", recorder.Body.String())
	}
}
