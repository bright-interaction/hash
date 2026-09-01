// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/recipients"
)

var errOIDCSubjectMismatch = errors.New("OIDC subject does not match the account's bound identity")

// handleAuthLogin redirects the browser to Zitadel.
//
// s.OIDC is nil whenever auth.NewOIDC failed at boot, which main.go treats as a
// SUPPORTED state ("in local dev without a working IdP we still want the server
// to come up, just without /auth/login working"). It came up without the second
// half: an unauthenticated GET to this route dereferenced the nil OIDC inside
// Login and panicked, which the recovery middleware turned into a 500 plus a
// FATAL Flare event. Production hash runs with no OIDC_* variables set at all,
// so every hit on these two public routes, including from a bot sweeping common
// auth paths, paged us with a crash report. Answer honestly instead.
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		writeError(w, http.StatusServiceUnavailable, "single sign-on is not configured on this instance")
		return
	}
	s.OIDC.Login(w, r)
}

// handleAuthCallback finishes the OIDC dance, finds-or-creates the user
// record in our DB, and mints the session cookie.
func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Same nil-OIDC exposure as handleAuthLogin above; this route is public too.
	if s.OIDC == nil {
		writeError(w, http.StatusServiceUnavailable, "single sign-on is not configured on this instance")
		return
	}
	auth.ClearOIDCLoginCookies(w)

	sub, email, name, emailVerified, err := s.OIDC.Callback(ctx, r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "auth callback failed")
		return
	}
	sub, err = normalizeOIDCSubject(sub)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "auth callback returned an invalid subject")
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
		// A previously unseen OIDC subject may only create/adopt an account with a
		// provider-verified email. Creating a fresh owner from an unverified claim
		// still permits spoofed invitations and irreversible account ambiguity.
		if !emailVerified {
			writeError(w, http.StatusUnauthorized, "a verified email claim is required for first login")
			return
		}
		email, name, err = normalizeOIDCIdentity(email, name)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "auth callback returned an invalid identity")
			return
		}
		user, err = s.provisionOrAdoptOIDCUser(ctx, email, name, sub)
		if errors.Is(err, errOIDCSubjectMismatch) {
			writeError(w, http.StatusUnauthorized, "account is already bound to a different identity")
			return
		}
		if err != nil {
			writeInternalErrorMsg(w, "user provisioning failed", err)
			return
		}
	}

	if err := auth.MintSession(w, s.Cookies, SessionCookieName, auth.SessionPayload{
		UserID: user.ID,
	}, 24*time.Hour); err != nil {
		writeError(w, http.StatusInternalServerError, "session mint failed")
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// provisionOrAdoptOIDCUser binds an invited/legacy account by verified email,
// or atomically creates a fresh org and owner for a genuinely new identity.
func (s *Server) provisionOrAdoptOIDCUser(ctx context.Context, email, name, sub string) (*generated.User, error) {
	user, err := s.Queries.GetUserByEmail(ctx, email)
	if err == nil {
		return s.bindOIDCSubject(ctx, user, sub)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	user, createErr := s.bootstrapUser(ctx, email, name, sub)
	if createErr == nil {
		return user, nil
	}
	// Concurrent first-login callbacks can both observe no row. The unique
	// subject/email constraints choose one winner; recover the winner instead of
	// leaving the other browser at a spurious 500.
	if raced, lookupErr := s.Queries.GetUserByZitadelSub(ctx, pgtype.Text{String: sub, Valid: true}); lookupErr == nil {
		return raced, nil
	}
	if raced, lookupErr := s.Queries.GetUserByEmail(ctx, email); lookupErr == nil {
		return s.bindOIDCSubject(ctx, raced, sub)
	}
	return nil, createErr
}

func (s *Server) bindOIDCSubject(ctx context.Context, user *generated.User, sub string) (*generated.User, error) {
	if user == nil {
		return nil, errors.New("cannot bind a nil user")
	}
	if user.ZitadelSub.Valid {
		if user.ZitadelSub.String != sub {
			return nil, errOIDCSubjectMismatch
		}
		return user, nil
	}
	bound, err := audit.CommitMutation(ctx, s.Pool, s.Audit,
		func(q *generated.Queries) (*generated.User, error) {
			return q.BindUserZitadelSub(ctx, generated.BindUserZitadelSubParams{
				ID: user.ID, ZitadelSub: pgtype.Text{String: sub, Valid: true},
			})
		},
		func(bound *generated.User) audit.Entry {
			return audit.Entry{
				OrgID: bound.OrgID, ActorUserID: &bound.ID,
				Kind: audit.KindMemberIdentityBound,
				Payload: map[string]any{
					"member_id": bound.ID.String(), "provider": "oidc",
				},
			}
		},
	)
	if errors.Is(err, pgx.ErrNoRows) || isUniqueViolation(err) {
		return nil, errOIDCSubjectMismatch
	}
	return bound, err
}

func (s *Server) bootstrapUser(ctx context.Context, email, name, sub string) (*generated.User, error) {
	if s.Pool == nil || s.Audit == nil {
		return nil, errors.New("atomic account provisioning dependencies unavailable")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Queries.WithTx(tx)
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{
		Name: nameOrEmail(name, email),
		Plan: "starter",
	})
	if err != nil {
		return nil, err
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID:      org.ID,
		Email:      email,
		Name:       nameOrEmail(name, email),
		Role:       "owner",
		ZitadelSub: pgtype.Text{String: sub, Valid: true},
	})
	if err != nil {
		return nil, err
	}
	pending, err := s.Audit.LogTx(ctx, tx, audit.Entry{
		OrgID: org.ID, ActorUserID: &user.ID,
		Kind: audit.KindMemberCreated,
		Payload: map[string]any{
			"member_id": user.ID.String(), "role": user.Role, "bootstrap": true, "provider": "oidc",
		},
	})
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.Audit.Publish(pending)
	return user, nil
}

func normalizeOIDCSubject(sub string) (string, error) {
	if sub == "" || sub != strings.TrimSpace(sub) || len(sub) > 512 || !utf8.ValidString(sub) {
		return "", errors.New("invalid OIDC subject")
	}
	for _, r := range sub {
		if unicode.IsControl(r) {
			return "", errors.New("invalid OIDC subject")
		}
	}
	return sub, nil
}

func normalizeOIDCIdentity(email, name string) (string, string, error) {
	// Validate the original byte sequence before case folding. strings.ToLower
	// replaces malformed UTF-8 with U+FFFD, which would otherwise turn an
	// invalid provider identity into a different, apparently valid address.
	email = strings.TrimSpace(email)
	name = strings.TrimSpace(name)
	hasProviderName := name != ""
	name = nameOrEmail(name, email)
	identity, err := recipients.Normalize(recipients.Values{
		Email: email, Name: name, Role: "signer", Locale: "en",
	})
	if err != nil {
		return "", "", err
	}
	identity.Email = strings.ToLower(identity.Email)
	if !hasProviderName {
		identity.Name = identity.Email
	}
	identity, err = recipients.Normalize(identity)
	if err != nil {
		return "", "", err
	}
	return identity.Email, identity.Name, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
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
