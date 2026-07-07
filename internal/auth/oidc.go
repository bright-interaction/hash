package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDC wraps a Zitadel-issued OpenID Connect provider for sender login.
type OIDC struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth2   *oauth2.Config
	cookies  *SignedCookie
}

type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Cookies      *SignedCookie
}

func NewOIDC(ctx context.Context, cfg OIDCConfig) (*OIDC, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	return &OIDC{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth2: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		cookies: cfg.Cookies,
	}, nil
}

// Login redirects the browser to the IdP authorize endpoint with a
// crypto-random state cookie for CSRF protection.
func (o *OIDC) Login(w http.ResponseWriter, r *http.Request) {
	state, err := randomString(24)
	if err != nil {
		http.Error(w, "state generation failed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "hash_oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(10 * time.Minute),
	})
	http.Redirect(w, r, o.oauth2.AuthCodeURL(state), http.StatusFound)
}

// Callback exchanges the authorization code for an ID token and returns the
// claims subject + email if everything checks out.
func (o *OIDC) Callback(ctx context.Context, r *http.Request) (sub, email, name string, emailVerified bool, err error) {
	stateCookie, err := r.Cookie("hash_oauth_state")
	if err != nil {
		return "", "", "", false, errors.New("missing state cookie")
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		return "", "", "", false, errors.New("state mismatch")
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		return "", "", "", false, errors.New("missing code")
	}
	tok, err := o.oauth2.Exchange(ctx, code)
	if err != nil {
		return "", "", "", false, fmt.Errorf("token exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		return "", "", "", false, errors.New("no id_token in response")
	}
	idTok, err := o.verifier.Verify(ctx, rawID)
	if err != nil {
		return "", "", "", false, fmt.Errorf("verify id_token: %w", err)
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
