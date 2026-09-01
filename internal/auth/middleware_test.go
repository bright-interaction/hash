// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/db/generated"
)

type sessionUserStoreStub struct {
	user      *generated.User
	err       error
	requested uuid.UUID
}

func (s *sessionUserStoreStub) GetUser(_ context.Context, id uuid.UUID) (*generated.User, error) {
	s.requested = id
	return s.user, s.err
}

func signedSessionRequest(t *testing.T, cookies *SignedCookie, sp SessionPayload) *http.Request {
	t.Helper()
	payload, err := json.Marshal(sp)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: "hash_session", Value: cookies.Mint(payload, time.Hour)})
	return req
}

func TestRequireSessionUsesLiveDatabaseRoleOrgAndIdentity(t *testing.T) {
	cookies, err := NewSignedCookie(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	userID := uuid.New()
	liveOrg := uuid.New()
	staleCookieOrg := uuid.New()
	store := &sessionUserStoreStub{user: &generated.User{
		ID: userID, OrgID: liveOrg, Role: "viewer", Email: "current@example.com",
	}}
	req := signedSessionRequest(t, cookies, SessionPayload{
		UserID: userID,
		OrgID:  staleCookieOrg,
		Role:   "owner",
		Email:  "stale@example.com",
	})

	var got SessionUser
	h := RequireSession(cookies, "hash_session", store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		got, ok = FromContext(r.Context())
		if !ok {
			t.Fatal("session user missing from context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rr.Code)
	}
	if got.Role != "viewer" || got.OrgID != liveOrg || got.Email != "current@example.com" {
		t.Fatalf("context used stale cookie claims: %+v", got)
	}
	if got.OrgID == staleCookieOrg {
		t.Fatalf("context retained stale cookie org %s", staleCookieOrg)
	}
	if store.requested != userID {
		t.Fatalf("looked up %s, want %s", store.requested, userID)
	}
}

func TestMintSessionCookieContainsOnlyUserReference(t *testing.T) {
	cookies, err := NewSignedCookie(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	userID := uuid.New()
	orgID := uuid.New()
	rr := httptest.NewRecorder()
	if err := MintSession(rr, cookies, "hash_session", SessionPayload{
		UserID: userID,
		OrgID:  orgID,
		Role:   "owner",
		Email:  "private@example.test",
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	set := rr.Result().Cookies()
	if len(set) != 1 {
		t.Fatalf("set cookies = %d, want 1", len(set))
	}
	payload, err := cookies.Verify(set[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 || claims["u"] != userID.String() {
		t.Fatalf("session cookie disclosed more than the user reference: %s", payload)
	}
	for _, secret := range []string{orgID.String(), "owner", "private@example.test"} {
		if strings.Contains(string(payload), secret) {
			t.Fatalf("session cookie payload leaked %q: %s", secret, payload)
		}
	}
}

func TestRequireSessionDemotionImmediatelyRevokesOwnerRoute(t *testing.T) {
	cookies, _ := NewSignedCookie(strings.Repeat("a", 64))
	userID := uuid.New()
	store := &sessionUserStoreStub{user: &generated.User{
		ID: userID, OrgID: uuid.New(), Role: "viewer", Email: "member@example.com",
	}}
	req := signedSessionRequest(t, cookies, SessionPayload{
		UserID: userID, OrgID: store.user.OrgID, Role: "owner", Email: store.user.Email,
	})

	ownerOnly := RequireRole(RoleOwner)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("demoted user reached owner handler")
	}))
	h := RequireSession(cookies, "hash_session", store)(ownerOnly)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
}

func TestRequireSessionDeletedUserIsUnauthorizedAndCookieCleared(t *testing.T) {
	cookies, _ := NewSignedCookie(strings.Repeat("a", 64))
	userID := uuid.New()
	store := &sessionUserStoreStub{err: pgx.ErrNoRows}
	req := signedSessionRequest(t, cookies, SessionPayload{
		UserID: userID, OrgID: uuid.New(), Role: "sender", Email: "gone@example.com",
	})
	h := RequireSession(cookies, "hash_session", store)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("deleted user reached handler")
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	cleared := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "hash_session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("deleted user's session cookie was not cleared")
	}
}

func TestRequireSessionDatabaseFailureFailsClosed(t *testing.T) {
	cookies, _ := NewSignedCookie(strings.Repeat("a", 64))
	userID := uuid.New()
	store := &sessionUserStoreStub{err: errors.New("database unavailable")}
	req := signedSessionRequest(t, cookies, SessionPayload{
		UserID: userID, OrgID: uuid.New(), Role: "owner", Email: "owner@example.com",
	})
	h := RequireSession(cookies, "hash_session", store)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request reached handler during authorization DB failure")
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}
