// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package i18n

import "testing"

func TestT_FallbackAndParams(t *testing.T) {
	// Known Swedish key resolves to a non-empty, non-key value.
	if got := T("sv", "email.invite.cta", nil); got == "" || got == "email.invite.cta" {
		t.Errorf("sv cta unresolved: %q", got)
	}
	// Unknown key passes through.
	if got := T("sv", "no.such.key", nil); got != "no.such.key" {
		t.Errorf("want key passthrough, got %q", got)
	}
	// Unknown locale falls back to English per key.
	if got, want := T("zz", "email.invite.cta", nil), T("en", "email.invite.cta", nil); got != want {
		t.Errorf("unknown locale should fall back to en: got %q want %q", got, want)
	}
	// Placeholder substitution.
	if got := T("en", "email.invite.subject", map[string]string{"sender": "Jane", "document": "NDA"}); got != "Jane sent you NDA for signature" {
		t.Errorf("substitution: %q", got)
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{"": "en", "zz": "en", "sv": "sv", "de": "de"}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEveryLocaleHasInviteSubject(t *testing.T) {
	// Spot-check coverage: every shipped locale has the invite subject and it
	// keeps both placeholders.
	for code := range messages {
		s := T(code, "email.invite.subject", map[string]string{"sender": "S", "document": "D"})
		if s == "" || s == "email.invite.subject" {
			t.Errorf("%s: invite subject unresolved", code)
		}
		if !contains(s, "S") || !contains(s, "D") {
			t.Errorf("%s: invite subject dropped a placeholder value: %q", code, s)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
