// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package recipients

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeRecipient(t *testing.T) {
	got, err := Normalize(Values{
		Email: "  signer@example.test  ", Name: "  Åsa Öberg  ",
		Role: " SIGNER ", OrderIndex: 7, Locale: " SV ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != "signer@example.test" || got.Name != "Åsa Öberg" || got.Role != "signer" || got.Locale != "sv" {
		t.Fatalf("normalized recipient = %#v", got)
	}
}

func TestNormalizeRecipientCanonicalizesSupportedRegionalLocale(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "sv-SE", want: "sv"},
		{input: "EN_gb", want: "en"},
		{input: "pt-BR-u-ca-gregory", want: "pt"},
	} {
		got, err := Normalize(Values{
			Email: "signer@example.test", Name: "Signer", Role: "signer", Locale: test.input,
		})
		if err != nil {
			t.Fatalf("Normalize(locale=%q): %v", test.input, err)
		}
		if got.Locale != test.want {
			t.Fatalf("Normalize(locale=%q) = %q, want %q", test.input, got.Locale, test.want)
		}
	}
}

func TestNormalizeRecipientAllowsCanonicalCustomSigningRole(t *testing.T) {
	got, err := Normalize(Values{
		Email: "client@example.test", Name: "Client", Role: " Client_Signer ", Locale: "en",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != "client_signer" {
		t.Fatalf("role = %q, want client_signer", got.Role)
	}
}

func TestNormalizeRecipientRejectsInvalidFields(t *testing.T) {
	valid := Values{Email: "signer@example.test", Name: "Signer", Role: "signer", Locale: "en"}
	tests := []struct {
		name, field string
		mutate      func(*Values)
	}{
		{"display name email", "email", func(v *Values) { v.Email = "Signer <signer@example.test>" }},
		{"invalid email UTF-8", "email", func(v *Values) { v.Email = string([]byte{0xff}) + "@example.test" }},
		{"control in email", "email", func(v *Values) { v.Email = "signer\x00@example.test" }},
		{"overlong email", "email", func(v *Values) { v.Email = strings.Repeat("a", MaxEmailBytes) + "@x" }},
		{"empty name", "name", func(v *Values) { v.Name = " \t " }},
		{"control in name", "name", func(v *Values) { v.Name = "Signer\nInjected" }},
		{"too many name runes", "name", func(v *Values) { v.Name = strings.Repeat("å", MaxNameRunes+1) }},
		{"invalid role", "role", func(v *Values) { v.Role = "owner role" }},
		{"negative order", "order_index", func(v *Values) { v.OrderIndex = -1 }},
		{"large order", "order_index", func(v *Values) { v.OrderIndex = MaxOrderIndex + 1 }},
		{"unknown locale", "locale", func(v *Values) { v.Locale = "xx" }},
		{"unknown regional locale", "locale", func(v *Values) { v.Locale = "zh-CN" }},
		{"malformed regional locale", "locale", func(v *Values) { v.Locale = "sv--SE" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := valid
			tt.mutate(&input)
			_, err := Normalize(input)
			var validationErr *ValidationError
			if !errors.As(err, &validationErr) || validationErr.Field != tt.field {
				t.Fatalf("error = %v, want ValidationError for %s", err, tt.field)
			}
		})
	}
}

func TestValidatePersistedRejectsNonCanonicalRow(t *testing.T) {
	err := ValidatePersisted(Values{
		Email: " signer@example.test ", Name: "Signer", Role: "signer", Locale: "en",
	})
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) || validationErr.Field != "email" {
		t.Fatalf("error = %v, want non-canonical email error", err)
	}
}

func TestHasTerminalResponseCoversBothCeremonyModes(t *testing.T) {
	for _, status := range []string{"signed", "accepted"} {
		if !HasTerminalResponse(status) {
			t.Errorf("terminal response status %q was rejected", status)
		}
	}
	for _, status := range []string{"pending", "sent", "viewed", "declined", "bounced", "completed", ""} {
		if HasTerminalResponse(status) {
			t.Errorf("non-terminal response status %q was accepted", status)
		}
	}
}

func TestCanRespondSupportsCustomRolesButNotInformationalRoles(t *testing.T) {
	for _, role := range []string{"signer", "approver", "client", "provider_signer"} {
		if !CanRespond(role) {
			t.Errorf("response role %q was rejected", role)
		}
	}
	for _, role := range []string{"cc", "viewer", "Owner", "bad role", ""} {
		if CanRespond(role) {
			t.Errorf("unsupported response role %q was accepted", role)
		}
		if err := ValidateResponseRole(role); err == nil {
			t.Errorf("ValidateResponseRole(%q) succeeded", role)
		}
	}
}
