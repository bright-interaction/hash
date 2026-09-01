// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"context"
	"testing"
)

func ctxWithScopes(scopes []string, set bool) context.Context {
	ctx := context.Background()
	if set {
		ctx = context.WithValue(ctx, TokenScopesKey, scopes)
	}
	return ctx
}

func TestHasWriteScope(t *testing.T) {
	cases := []struct {
		name   string
		scopes []string
		set    bool
		want   bool
	}{
		{"no scope set (session cookie) => full access", nil, false, true},
		{"empty API-token scope slice => fail closed", []string{}, true, false},
		{"read only => blocked", []string{"read"}, true, false},
		{"read + write:authoring => allowed", []string{"read", "write:authoring"}, true, true},
		{"read + write:workflow => allowed", []string{"read", "write:workflow"}, true, true},
		{"doc-token plain write => allowed", []string{"read", "write"}, true, true},
		{"admin => allowed", []string{"admin"}, true, true},
		{"sign only (doc token) => blocked from writes", []string{"read", "sign"}, true, false},
	}
	for _, c := range cases {
		if got := HasWriteScope(ctxWithScopes(c.scopes, c.set)); got != c.want {
			t.Errorf("%s: HasWriteScope = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestHasScope_ExactAndAdmin(t *testing.T) {
	if !HasScope(ctxWithScopes(nil, false), "anything") {
		t.Error("no scope set should be full access")
	}
	if HasScope(ctxWithScopes([]string{"read"}, true), "write") {
		t.Error("read-only token should not have write scope")
	}
	if HasScope(ctxWithScopes([]string{}, true), "read") {
		t.Error("empty API-token scope set should fail closed")
	}
	if !HasScope(ctxWithScopes([]string{"admin"}, true), "write") {
		t.Error("admin should imply write")
	}
	if !HasScope(ctxWithScopes([]string{"read"}, true), "read") {
		t.Error("read token should have read scope")
	}
}
