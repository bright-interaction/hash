// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package generated

import (
	"os"
	"strings"
	"testing"
)

func TestRecipientStatusMutationPreservesAcceptedEvidence(t *testing.T) {
	raw, err := os.ReadFile("../queries/recipients.sql")
	if err != nil {
		t.Fatal(err)
	}
	query := string(raw)
	if !strings.Contains(query, "status NOT IN ('signed','accepted','declined')") {
		t.Fatal("SetRecipientStatus does not treat accepted acknowledgement evidence as terminal")
	}
	if !strings.Contains(setRecipientStatus, "status NOT IN ('signed','accepted','declined')") {
		t.Fatal("generated SetRecipientStatus is stale or does not preserve accepted evidence")
	}
}
