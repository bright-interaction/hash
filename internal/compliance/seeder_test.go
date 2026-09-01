// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package compliance

import "testing"

func TestNormalizeJurisdictionSupportsOnlySweden(t *testing.T) {
	for _, input := range []string{"", "SE", " se "} {
		got, err := NormalizeJurisdiction(input)
		if err != nil || got != "SE" {
			t.Fatalf("NormalizeJurisdiction(%q) = %q, %v", input, got, err)
		}
	}
	for _, input := range []string{"NO", "DE", "SWE", "EU"} {
		if got, err := NormalizeJurisdiction(input); err == nil || got != "" {
			t.Errorf("NormalizeJurisdiction(%q) = %q, %v; want rejection", input, got, err)
		}
	}
}
