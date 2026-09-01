// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"strings"
	"testing"
)

func TestNormalizeOIDCSubject(t *testing.T) {
	t.Parallel()

	for _, subject := range []string{"user-123", "urn:issuer:subject", strings.Repeat("a", 512)} {
		subject := subject
		t.Run("valid_"+subject[:min(8, len(subject))], func(t *testing.T) {
			t.Parallel()
			got, err := normalizeOIDCSubject(subject)
			if err != nil || got != subject {
				t.Fatalf("normalizeOIDCSubject(%q) = %q, %v", subject, got, err)
			}
		})
	}

	for name, subject := range map[string]string{
		"empty":           "",
		"leading space":   " user-123",
		"trailing space":  "user-123 ",
		"control":         "user\n123",
		"invalid UTF-8":   string([]byte{0xff}),
		"more than 512 B": strings.Repeat("a", 513),
	} {
		name, subject := name, subject
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := normalizeOIDCSubject(subject); err == nil {
				t.Fatalf("normalizeOIDCSubject(%q) unexpectedly succeeded", subject)
			}
		})
	}
}

func TestNormalizeOIDCIdentity(t *testing.T) {
	t.Parallel()

	email, name, err := normalizeOIDCIdentity(" Owner@Example.COM ", "  Jane Owner  ")
	if err != nil {
		t.Fatal(err)
	}
	if email != "owner@example.com" || name != "Jane Owner" {
		t.Fatalf("got email=%q name=%q", email, name)
	}

	email, name, err = normalizeOIDCIdentity("Fallback@Example.COM", "")
	if err != nil {
		t.Fatal(err)
	}
	if email != "fallback@example.com" || name != email {
		t.Fatalf("email fallback got email=%q name=%q", email, name)
	}

	for testName, input := range map[string]struct{ email, name string }{
		"missing email":      {name: "Owner"},
		"display address":    {email: "Owner <owner@example.com>", name: "Owner"},
		"invalid name":       {email: "owner@example.com", name: "Owner\nAdmin"},
		"oversized name":     {email: "owner@example.com", name: strings.Repeat("x", 201)},
		"invalid email UTF8": {email: string([]byte{0xff}) + "@example.com", name: "Owner"},
		"email control":      {email: "owner\x00@example.com", name: "Owner"},
	} {
		testName, input := testName, input
		t.Run(testName, func(t *testing.T) {
			t.Parallel()
			if _, _, err := normalizeOIDCIdentity(input.email, input.name); err == nil {
				t.Fatalf("normalizeOIDCIdentity(%q, %q) unexpectedly succeeded", input.email, input.name)
			}
		})
	}
}
