// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// SessionPayload is the JSON we sign + store in the session cookie. Only the
// stable user reference is serialized. The other fields remain source-compatible
// hints for callers/tests but are deliberately excluded so email, tenant, and
// privilege data are neither disclosed to the browser nor trusted for auth.
type SessionPayload struct {
	UserID uuid.UUID `json:"u"`
	OrgID  uuid.UUID `json:"-"`
	Role   string    `json:"-"`
	Email  string    `json:"-"`
}

// SessionUserStore is the live authorization source for cookie sessions.
// Signed cookies authenticate the session but do not authorize a role for
// their full TTL: membership, tenant, role, and email are reloaded on every
// request so a demotion or deletion takes effect immediately.
type SessionUserStore interface {
	GetUser(context.Context, uuid.UUID) (*generated.User, error)
}

// RequireSession is the chi-compatible middleware that enforces a valid
// signed session cookie. On success it injects SessionUser into the context.
func RequireSession(cookies *SignedCookie, cookieName string, users SessionUserStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(cookieName)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			payload, err := cookies.Verify(c.Value)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			var sp SessionPayload
			if err := json.Unmarshal(payload, &sp); err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if sp.UserID == uuid.Nil || users == nil {
				if users == nil {
					http.Error(w, "session authorization unavailable", http.StatusServiceUnavailable)
				} else {
					ClearSession(w, cookieName)
					http.Error(w, "unauthorized", http.StatusUnauthorized)
				}
				return
			}

			// Loading the canonical row closes the 24-hour stale-privilege window
			// after an owner demotes or removes a member. Legacy cookies may still
			// carry old org/role/email JSON keys; decoding ignores those values.
			user, err := users.GetUser(r.Context(), sp.UserID)
			if errors.Is(err, pgx.ErrNoRows) {
				ClearSession(w, cookieName)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if err != nil {
				http.Error(w, "session authorization unavailable", http.StatusServiceUnavailable)
				return
			}
			if user == nil || user.ID != sp.UserID || user.OrgID == uuid.Nil || !validSessionRole(user.Role) {
				ClearSession(w, cookieName)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := r.Context()
			ctx = context.WithValue(ctx, UserIDKey, user.ID)
			ctx = context.WithValue(ctx, OrgIDKey, user.OrgID)
			ctx = context.WithValue(ctx, RoleKey, user.Role)
			ctx = context.WithValue(ctx, EmailKey, user.Email)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func validSessionRole(role string) bool {
	switch role {
	case string(RoleOwner), string(RoleSender), string(RoleViewer):
		return true
	}
	return false
}

// MintSession serializes a SessionPayload, signs it, and writes the cookie.
func MintSession(w http.ResponseWriter, cookies *SignedCookie, name string, sp SessionPayload, ttl time.Duration) error {
	body, err := json.Marshal(sp)
	if err != nil {
		return err
	}
	tok := cookies.Mint(body, ttl)
	http.SetCookie(w, cookies.Cookie(name, tok, ttl))
	return nil
}

// ClearSession overwrites the session cookie with an immediate-expiry one.
func ClearSession(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
