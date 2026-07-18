// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/db/generated"
)

// handleAuthLogin redirects the browser to Zitadel.
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	s.OIDC.Login(w, r)
}

// handleAuthCallback finishes the OIDC dance, finds-or-creates the user
// record in our DB, and mints the session cookie.
func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sub, email, name, emailVerified, err := s.OIDC.Callback(ctx, r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "auth callback failed")
		return
	}
	if email == "" {
		writeError(w, http.StatusBadRequest, "id_token missing email claim")
		return
	}

	// Find-or-create the user. First try by Zitadel sub (the stable identifier; safe
	// to trust). A sub match is used regardless of email_verified.
	user, err := s.Queries.GetUserByZitadelSub(ctx, pgtype.Text{String: sub, Valid: true})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		// A transient DB error (pool exhaustion, timeout) is NOT "no such user".
		// Treating it as one would fork a duplicate org for a returning user
		// during a hiccup, orphaning them from their real org + documents. Fail.
		writeInternalError(w, err)
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		// No stable-sub match. Only ADOPT an existing account by email when the IdP
		// asserts the email is verified; otherwise an attacker presenting an
		// unverified email claim equal to a victim owner's address would link straight
		// onto the victim's org + role (cross-tenant account takeover). Unverified ->
		// provision a fresh user/org, never link to an existing one.
		if emailVerified {
			user, err = s.Queries.GetUserByEmail(ctx, email)
			if errors.Is(err, pgx.ErrNoRows) {
				user, err = s.bootstrapUser(ctx, email, name, sub)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "user provisioning failed")
					return
				}
			} else if err != nil {
				writeError(w, http.StatusInternalServerError, "user lookup failed")
				return
			}
		} else {
			user, err = s.bootstrapUser(ctx, email, name, sub)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "user provisioning failed")
				return
			}
		}
	}

	if err := auth.MintSession(w, s.Cookies, SessionCookieName, auth.SessionPayload{
		UserID: user.ID,
		OrgID:  user.OrgID,
		Role:   user.Role,
		Email:  user.Email,
	}, 24*time.Hour); err != nil {
		writeError(w, http.StatusInternalServerError, "session mint failed")
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// bootstrapUser creates a fresh org + first user. Used the first time a
// brand-new email signs in.
func (s *Server) bootstrapUser(ctx interface {
	Done() <-chan struct{}
	Err() error
	Value(any) any
	Deadline() (time.Time, bool)
}, email, name, sub string) (*generated.User, error) {
	org, err := s.Queries.CreateOrg(ctx, generated.CreateOrgParams{
		Name: nameOrEmail(name, email),
		Plan: "starter",
	})
	if err != nil {
		return nil, err
	}
	user, err := s.Queries.CreateUser(ctx, generated.CreateUserParams{
		OrgID:      org.ID,
		Email:      email,
		Name:       nameOrEmail(name, email),
		Role:       "owner",
		ZitadelSub: pgtype.Text{String: sub, Valid: true},
	})
	if err != nil {
		return nil, err
	}
	return user, nil
}

func nameOrEmail(name, email string) string {
	if name != "" {
		return name
	}
	return email
}

// handleAuthLogout clears the session cookie.
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	auth.ClearSession(w, SessionCookieName)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// guard: use uuid pkg so the import is always referenced
var _ = uuid.Nil
