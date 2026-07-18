// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"context"
	"net/http"
)

// Org roles, lowest to highest privilege. The users.role column constrains the
// stored value to exactly these (migration 00001). Higher ranks inherit every
// lower-rank capability.
type Role string

const (
	RoleViewer Role = "viewer" // read-only: list/read documents, dashboards, timelines
	RoleSender Role = "sender" // create/edit/send documents, recipients, fields, AI
	RoleOwner  Role = "owner"  // everything, plus org settings + member management
)

func roleRank(r string) int {
	switch r {
	case "owner":
		return 3
	case "sender":
		return 2
	case "viewer":
		return 1
	}
	return 0 // unknown / unset: below every named role, so fail-closed
}

// RoleAtLeast reports whether the request context's role meets the minimum.
// The role is set by RequireSession (session cookie) and the API-key middleware
// (the key inherits its user's role), so this works for both auth modes. A
// missing role ranks below viewer and is refused.
func RoleAtLeast(ctx context.Context, min Role) bool {
	role, _ := ctx.Value(RoleKey).(string)
	return roleRank(role) >= roleRank(string(min))
}

// forbid writes a 403 with a small JSON body.
func forbid(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"insufficient role for this action"}`))
}

// RequireRole is middleware that refuses (403) any request whose role is below
// min, for every method. Use it on admin-only route groups (org settings,
// member management).
func RequireRole(min Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !RoleAtLeast(r.Context(), min) {
				forbid(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRoleForWrites lets safe (read) methods through for any authenticated
// user but requires `min` for mutations. Use it on groups that mix reads and
// writes (documents, templates) so viewers keep read access while only
// senders+ can create/edit/send. Future write routes added to the group are
// covered automatically.
func RequireRoleForWrites(min Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}
			if !RoleAtLeast(r.Context(), min) {
				forbid(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
