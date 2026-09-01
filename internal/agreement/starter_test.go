// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package agreement

import (
	"slices"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/blocks"
)

func TestServicesAgreementRequiresCurrentPartyAndDateValues(t *testing.T) {
	requiredAtInstantiation := []string{
		"provider_orgnr", "client", "client_orgnr", "client_signatory",
		"client_title", "effective_date", "offer_valid_until",
		"legal_approval_reference", "dpa_reference",
	}
	referenced := blocks.ExtractVariableNames(&ServicesAgreement.Tree)
	for _, key := range requiredAtInstantiation {
		if !slices.Contains(referenced, key) {
			t.Fatalf("starter no longer references required variable %q", key)
		}
		if value, prefilled := ServicesAgreement.Variables[key]; prefilled {
			t.Fatalf("required variable %q has unsafe built-in value %q", key, value)
		}
	}
}

func TestServicesAgreementDoesNotInventLicensingOrAttachments(t *testing.T) {
	text := string(ServicesAgreement.BlocksJSON())
	for _, forbidden := range []string{"Apache 2.0", "Bilaga A", "öppen källkod"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("starter still contains unsupported claim %q", forbidden)
		}
	}
}
