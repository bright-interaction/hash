// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDC wraps a Zitadel-issued OpenID Connect provider for sender login.
//
// Discovery is resolved LAZILY and retried, not resolved once at boot.
// oidc.NewProvider performs a network fetch of
// <issuer>/.well-known/openid-configuration, and this used to run exactly once
// in NewOIDC. If the IdP was unreachable at that instant, main.go logged a
// warning, set the pointer to nil, and single sign-on was dead for the entire
// process lifetime with a container restart as the only recovery. That is not
// theoretical: prod hash booted 2026-07-29 02:02 into that state with a fully
// populated /opt/hash/.env and served nothing but failures on /auth/login until
// it was redeployed the next day.
//
// A momentary IdP blip during our startup must not be a permanent outage, so
// the endpoints resolve on first use and every subsequent attempt retries until
// one succeeds. Callers get a clean 503 in the meantime.
type OIDC struct {
	cfg     OIDCConfig
	cookies *SignedCookie

	// mu guards the resolved-once endpoints below. Held across the discovery
	// fetch so concurrent first logins do not stampede the IdP; after success
	// it is only ever taken for a pointer read.
	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
	oauth2   *oauth2.Config
}

// resolve returns the discovered endpoints, performing discovery on first use
// and retrying on each call until it succeeds. The result is cached forever
// once obtained.
func (o *OIDC) resolve(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.oauth2 != nil {
		return o.oauth2, o.verifier, nil
	}
	timeout := o.cfg.DiscoveryTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	provider, err := oidc.NewProvider(discoveryCtx, o.cfg.IssuerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc discovery: %w", err)
	}
	o.verifier = provider.Verifier(&oidc.Config{ClientID: o.cfg.ClientID})
	o.oauth2 = &oauth2.Config{
		ClientID:     o.cfg.ClientID,
		ClientSecret: o.cfg.ClientSecret,
		RedirectURL:  o.cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return o.oauth2, o.verifier, nil
}

// unavailable answers a request that arrived while discovery has still never
// succeeded. Distinct from the handler's "not configured" 503 in server-side
// logs only; to a browser both are "SSO is not available right now".
func (o *OIDC) unavailable(w http.ResponseWriter, err error) {
	slog.Warn("oidc: discovery has not succeeded yet; SSO unavailable", "issuer", o.cfg.IssuerURL, "err", err)
	http.Error(w, "single sign-on is temporarily unavailable", http.StatusServiceUnavailable)
}

type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Cookies      *SignedCookie
	// DiscoveryTimeout bounds both the boot probe and each lazy retry. Zero
	// selects the production default (10 seconds).
	DiscoveryTimeout time.Duration
}

// NewOIDC returns an OIDC for cfg. It attempts discovery immediately so a
// genuinely broken issuer is loud in the boot log, but a discovery FAILURE
// still yields a usable *OIDC (returned alongside the error) which retries on
// demand. Callers must keep that value rather than discarding it on error;
// dropping it is what turned a transient blip into a permanent SSO outage.
//
// A missing issuer is the one case that yields nil: SSO is genuinely not
// configured, there is nothing to retry, and the handlers answer 503.
func NewOIDC(ctx context.Context, cfg OIDCConfig) (*OIDC, error) {
	if cfg.IssuerURL == "" {
		return nil, errors.New("oidc: no issuer configured")
	}
	o := &OIDC{cfg: cfg, cookies: cfg.Cookies}
	if _, _, err := o.resolve(ctx); err != nil {
		return o, err
	}
	return o, nil
}

// Login redirects the browser to the IdP authorize endpoint with a
// crypto-random state cookie (CSRF), a nonce (binds the id_token to this
// request), and a PKCE S256 challenge (binds the code to this client without a
// client secret). The estate's Zitadel apps are public PKCE clients, so PKCE is
// required, not optional.
func (o *OIDC) Login(w http.ResponseWriter, r *http.Request) {
	conf, _, err := o.resolve(r.Context())
	if err != nil {
		o.unavailable(w, err)
		return
	}
	state, err := randomString(24)
	if err != nil {
		http.Error(w, "state generation failed", http.StatusInternalServerError)
		return
	}
	nonce, err := randomString(24)
	if err != nil {
		http.Error(w, "nonce generation failed", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	setLoginCookie(w, "hash_oauth_state", state)
	setLoginCookie(w, "hash_oauth_nonce", nonce)
	setLoginCookie(w, "hash_oauth_verifier", verifier)
	url := conf.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, url, http.StatusFound)
}

// setLoginCookie writes one short-lived HttpOnly leg of the login handshake
// (state / nonce / PKCE verifier).
func setLoginCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(10 * time.Minute),
	})
}

// ClearOIDCLoginCookies removes the one-use state, nonce, and PKCE verifier
// after the callback request has received them. They expire after ten minutes
// regardless, but clearing them immediately narrows replay exposure and keeps
// the public cookie notice exact.
func ClearOIDCLoginCookies(w http.ResponseWriter) {
	for _, name := range []string{"hash_oauth_state", "hash_oauth_nonce", "hash_oauth_verifier"} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", HttpOnly: true, Secure: true,
			SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0),
		})
	}
}

// Callback exchanges the authorization code for an ID token and returns the
// claims subject + email if everything checks out.
func (o *OIDC) Callback(ctx context.Context, r *http.Request) (sub, email, name string, emailVerified bool, err error) {
	conf, idVerifier, err := o.resolve(ctx)
	if err != nil {
		return "", "", "", false, fmt.Errorf("oidc unavailable: %w", err)
	}
	stateCookie, err := r.Cookie("hash_oauth_state")
	if err != nil {
		return "", "", "", false, errors.New("missing state cookie")
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		return "", "", "", false, errors.New("state mismatch")
	}
	verifierCookie, err := r.Cookie("hash_oauth_verifier")
	if err != nil {
		return "", "", "", false, errors.New("missing PKCE verifier cookie")
	}
	nonceCookie, err := r.Cookie("hash_oauth_nonce")
	if err != nil {
		return "", "", "", false, errors.New("missing nonce cookie")
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		return "", "", "", false, errors.New("missing code")
	}
	tok, err := conf.Exchange(ctx, code, oauth2.VerifierOption(verifierCookie.Value))
	if err != nil {
		return "", "", "", false, fmt.Errorf("token exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		return "", "", "", false, errors.New("no id_token in response")
	}
	idTok, err := idVerifier.Verify(ctx, rawID)
	if err != nil {
		return "", "", "", false, fmt.Errorf("verify id_token: %w", err)
	}
	if idTok.Nonce != nonceCookie.Value {
		return "", "", "", false, errors.New("nonce mismatch")
	}
	// email_verified MUST be decoded and honored: the find-or-create path links an
	// existing account by email, so an unverified attacker-set email claim equal to a
	// victim owner's address would otherwise adopt the victim's org + role.
	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idTok.Claims(&claims); err != nil {
		return "", "", "", false, fmt.Errorf("decode claims: %w", err)
	}
	return claims.Sub, claims.Email, claims.Name, claims.EmailVerified, nil
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
