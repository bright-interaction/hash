// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/billing"
)

func TestSanitizeToolErrorEntitlementUnavailable(t *testing.T) {
	message := sanitizeToolError(&billing.EntitlementUnavailableError{
		Stage: "load usage", Err: errors.New("dial tcp postgres.internal:5432"),
	})
	if message != "billing entitlement check temporarily unavailable; retry later" {
		t.Fatalf("message = %q", message)
	}
	if strings.Contains(message, "postgres") || strings.Contains(message, "quota exceeded") {
		t.Fatalf("unsafe or misleading message = %q", message)
	}
}
