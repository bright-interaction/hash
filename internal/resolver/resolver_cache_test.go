// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package resolver

import (
	"testing"

	"github.com/google/uuid"
)

func TestInvalidateForSourceOrgsIsTenantScoped(t *testing.T) {
	resolver := New(nil)
	orgA := uuid.New()
	orgB := uuid.New()
	key := func(orgID uuid.UUID, kind, ref, path string) string {
		return orgID.String() + "|" + kind + "|" + ref + "|" + path
	}
	for cacheKey, value := range map[string]string{
		key(orgA, "crm.deal", "shared-ref", "amount"):  "a-amount",
		key(orgA, "crm.deal", "shared-ref", "stage"):   "a-stage",
		key(orgB, "crm.deal", "shared-ref", "amount"):  "b-amount",
		key(orgA, "crm.deal", "other-ref", "amount"):   "a-other",
		key(orgA, "crm.contact", "shared-ref", "name"): "a-contact",
	} {
		resolver.Cache.put(cacheKey, value)
	}

	if got := resolver.InvalidateForSourceOrgs("crm.deal", "shared-ref", []uuid.UUID{orgA}); got != 2 {
		t.Fatalf("invalidated entries = %d, want 2", got)
	}
	if _, ok := resolver.Cache.get(key(orgA, "crm.deal", "shared-ref", "amount")); ok {
		t.Fatal("authorized org cache entry survived invalidation")
	}
	for _, untouched := range []string{
		key(orgB, "crm.deal", "shared-ref", "amount"),
		key(orgA, "crm.deal", "other-ref", "amount"),
		key(orgA, "crm.contact", "shared-ref", "name"),
	} {
		if _, ok := resolver.Cache.get(untouched); !ok {
			t.Fatalf("unrelated or unaudited cache entry %q was removed", untouched)
		}
	}
	if got := resolver.InvalidateForSourceOrgs("crm.deal", "shared-ref", nil); got != 0 {
		t.Fatalf("empty tenant authorization invalidated %d entries", got)
	}
}
