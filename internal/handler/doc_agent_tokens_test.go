// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"slices"
	"testing"
	"time"
)

func TestNormalizeDocAgentScopesDefaultsReadOnly(t *testing.T) {
	got, err := normalizeDocAgentScopes(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"read"}) {
		t.Fatalf("default scopes = %v, want [read]", got)
	}
}

func TestNormalizeDocAgentScopesUsesGranularMCPVocabulary(t *testing.T) {
	want := []string{"read", "write:authoring", "write:workflow"}
	got, err := normalizeDocAgentScopes(want)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("scopes = %v, want %v", got, want)
	}
	for _, legacy := range []string{"write", "sign", "admin"} {
		if _, err := normalizeDocAgentScopes([]string{legacy}); err == nil {
			t.Errorf("new token unexpectedly accepted legacy/overbroad scope %q", legacy)
		}
	}
}

func TestDocAgentTokenTTLDaysContract(t *testing.T) {
	if got := docAgentTokenTTL(0); got != 7*24*time.Hour {
		t.Fatalf("default TTL = %s, want 7d", got)
	}
	if got := docAgentTokenTTL(30); got != 30*24*time.Hour {
		t.Fatalf("30-day TTL = %s", got)
	}
	if got := docAgentTokenTTL(999); got != 90*24*time.Hour {
		t.Fatalf("capped TTL = %s, want 90d", got)
	}
}
