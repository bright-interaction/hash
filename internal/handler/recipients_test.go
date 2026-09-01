// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/recipients"
)

func TestNormalizeRecipientUpdateDistinguishesOmittedAndExplicitEmpty(t *testing.T) {
	existing := &generated.Recipient{
		Email: "signer@example.test", Name: "Signer", Role: "signer", OrderIndex: 3, Locale: "en",
	}
	got, err := normalizeRecipientUpdate(existing, updateRecipientInput{})
	if err != nil {
		t.Fatalf("omitted update rejected: %v", err)
	}
	if got.Email != existing.Email || got.Name != existing.Name || got.OrderIndex != existing.OrderIndex {
		t.Fatalf("omitted update changed values: %#v", got)
	}

	empty := ""
	_, err = normalizeRecipientUpdate(existing, updateRecipientInput{Email: &empty})
	var validationErr *recipients.ValidationError
	if !errors.As(err, &validationErr) || validationErr.Field != "email" {
		t.Fatalf("explicit empty email error = %v, want email ValidationError", err)
	}
}

func TestNormalizeRecipientUpdateRejectsUnsupportedInformationalRole(t *testing.T) {
	existing := &generated.Recipient{
		Email: "signer@example.test", Name: "Signer", Role: "signer", Locale: "en",
	}
	for _, role := range []string{"cc", "viewer"} {
		role := role
		_, err := normalizeRecipientUpdate(existing, updateRecipientInput{Role: &role})
		var validationErr *recipients.ValidationError
		if !errors.As(err, &validationErr) || validationErr.Field != "role" {
			t.Fatalf("role %q error = %v, want role ValidationError", role, err)
		}
	}
}
