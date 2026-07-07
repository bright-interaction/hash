package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// SessionPayload is the JSON we sign + store in the session cookie.
type SessionPayload struct {
	UserID uuid.UUID `json:"u"`
	OrgID  uuid.UUID `json:"o"`
	Role   string    `json:"r"`
	Email  string    `json:"e"`
}

// RequireSession is the chi-compatible middleware that enforces a valid
// signed session cookie. On success it injects SessionUser into the context.
func RequireSession(cookies *SignedCookie, cookieName string) func(http.Handler) http.Handler {
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
			ctx := r.Context()
			ctx = context.WithValue(ctx, UserIDKey, sp.UserID)
			ctx = context.WithValue(ctx, OrgIDKey, sp.OrgID)
			ctx = context.WithValue(ctx, RoleKey, sp.Role)
			ctx = context.WithValue(ctx, EmailKey, sp.Email)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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
