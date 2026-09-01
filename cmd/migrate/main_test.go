// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"strings"
	"testing"
)

func TestRunRequiresDatabaseURL(t *testing.T) {
	err := run(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "HASH_DB_URL is required") {
		t.Fatalf("run with empty URL = %v, want explicit fail-closed error", err)
	}
}
