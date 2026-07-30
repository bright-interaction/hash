// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// discoveryStub serves the OIDC discovery document, but refuses until healthy
// is set. It models the real failure: the IdP is briefly unreachable while hash
// starts, then comes back.
func discoveryStub(t *testing.T) (*httptest.Server, *atomic.Bool, *atomic.Int32) {
	t.Helper()
	var healthy atomic.Bool
	var hits atomic.Int32

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if !healthy.Load() {
			http.Error(w, "idp is down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	return srv, &healthy, &hits
}

// A transient discovery failure at boot must not be a permanent SSO outage.
//
// Prod hash booted 2026-07-29 02:02 with a fully populated /opt/hash/.env,
// failed discovery once, and served nothing but failures on /auth/login until
// it was redeployed the next day. NewOIDC used to be the only attempt ever
// made, and main.go discarded the value on error.
func TestOIDCRecoversFromATransientDiscoveryFailure(t *testing.T) {
	srv, healthy, _ := discoveryStub(t)
	ctx := context.Background()

	o, err := NewOIDC(ctx, OIDCConfig{
		IssuerURL:   srv.URL,
		ClientID:    "hash",
		RedirectURL: "https://hash.example.com/auth/callback",
	})
	if err == nil {
		t.Fatal("expected the boot-time discovery against a down IdP to report an error")
	}
	if o == nil {
		t.Fatal("NewOIDC returned nil on a transient failure; that is the permanent-outage bug")
	}

	// While the IdP is down, login is refused cleanly rather than panicking.
	rec := httptest.NewRecorder()
	o.Login(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("login while the IdP is down: got %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	// The IdP comes back. No restart, no redeploy.
	healthy.Store(true)

	rec = httptest.NewRecorder()
	o.Login(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login after the IdP recovered: got %d, want %d (SSO did not self-heal)", rec.Code, http.StatusFound)
	}
	if loc := rec.Header().Get("Location"); loc == "" {
		t.Error("no redirect to the IdP authorize endpoint")
	}
}

// Once discovery succeeds the result is cached: a healthy login path must not
// re-fetch the discovery document on every request.
func TestOIDCResolvesDiscoveryOnlyOnceAfterSuccess(t *testing.T) {
	srv, healthy, hits := discoveryStub(t)
	healthy.Store(true)

	o, err := NewOIDC(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "hash", RedirectURL: "https://hash.example.com/auth/callback",
	})
	if err != nil {
		t.Fatalf("NewOIDC against a healthy IdP: %v", err)
	}
	after := hits.Load()

	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		o.Login(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
		if rec.Code != http.StatusFound {
			t.Fatalf("login %d: got %d, want %d", i, rec.Code, http.StatusFound)
		}
	}
	if got := hits.Load(); got != after {
		t.Errorf("discovery re-fetched %d extra times across 5 logins; it should be cached", got-after)
	}
}

// No issuer at all is a different state from a failed fetch: there is nothing
// to retry, so NewOIDC returns nil and the handlers answer "not configured".
func TestOIDCWithoutAnIssuerIsNil(t *testing.T) {
	o, err := NewOIDC(context.Background(), OIDCConfig{ClientID: "hash"})
	if err == nil {
		t.Fatal("expected an error when no issuer is configured")
	}
	if o != nil {
		t.Fatalf("expected nil so callers fall through to the not-configured 503, got %v", fmt.Sprintf("%T", o))
	}
}
