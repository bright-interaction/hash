// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import "testing"

func TestWritableRoutingTierAllowsOnlySES(t *testing.T) {
	for _, raw := range []string{"SES", "ses", " SES "} {
		got, err := writableRoutingTier(raw)
		if err != nil || got != "SES" {
			t.Fatalf("writableRoutingTier(%q) = %q, %v; want SES", raw, got, err)
		}
	}
	for _, raw := range []string{"AES", "QES", "", "unknown"} {
		if got, err := writableRoutingTier(raw); err == nil || got != "" {
			t.Fatalf("writableRoutingTier(%q) = %q, %v; want rejection", raw, got, err)
		}
	}
}
