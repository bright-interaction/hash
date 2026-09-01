// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/envelopes"
)

type routeAuthorizationDB struct {
	user generated.User
}

func (*routeAuthorizationDB) Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("unexpected exec")
}

func (*routeAuthorizationDB) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, errors.New("route reached its database handler")
}

func (db *routeAuthorizationDB) QueryRow(context.Context, string, ...interface{}) pgx.Row {
	return routeAuthorizationRow{user: db.user}
}

type routeAuthorizationRow struct {
	user generated.User
}

func (row routeAuthorizationRow) Scan(dest ...interface{}) error {
	if len(dest) != 7 {
		return errors.New("route reached a non-user query")
	}
	*(dest[0].(*uuid.UUID)) = row.user.ID
	*(dest[1].(*uuid.UUID)) = row.user.OrgID
	*(dest[2].(*string)) = row.user.Email
	*(dest[3].(*string)) = row.user.Name
	*(dest[4].(*string)) = row.user.Role
	*(dest[5].(*pgtype.Text)) = row.user.ZitadelSub
	*(dest[6].(*pgtype.Timestamptz)) = row.user.CreatedAt
	return nil
}

func authorizedRouteStatus(t *testing.T, role, method, target string) int {
	t.Helper()
	userID, orgID := uuid.New(), uuid.New()
	db := &routeAuthorizationDB{user: generated.User{
		ID: userID, OrgID: orgID, Email: "member@example.test", Name: "Member", Role: role,
		CreatedAt: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
	}}
	cookies, err := auth.NewSignedCookie(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	cookieResponse := httptest.NewRecorder()
	if err := auth.MintSession(cookieResponse, cookies, SessionCookieName, auth.SessionPayload{
		UserID: userID, OrgID: orgID, Role: role, Email: db.user.Email,
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	sessionCookies := cookieResponse.Result().Cookies()
	if len(sessionCookies) != 1 {
		t.Fatalf("session cookies = %d, want 1", len(sessionCookies))
	}

	srv := &Server{
		Cookies:   cookies,
		Queries:   generated.New(db),
		PublicURL: "https://hash.example.test",
		Envelopes: &envelopes.Engine{},
		Billing:   &billing.Engine{},
	}
	req := httptest.NewRequest(method, "https://hash.example.test"+target, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://hash.example.test")
	req.AddCookie(sessionCookies[0])
	res := httptest.NewRecorder()
	srv.Routes().ServeHTTP(res, req)
	return res.Code
}

func TestViewerCannotReachPrivilegedOrgMutationsOrSubjectExport(t *testing.T) {
	id := uuid.New().String()
	for _, test := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/envelopes/" + id + "/attach"},
		{http.MethodPost, "/api/v1/envelopes/" + id + "/detach"},
		{http.MethodPost, "/api/v1/envelopes/" + id + "/reorder"},
		{http.MethodGet, "/api/v1/dsr"},
		{http.MethodGet, "/api/v1/data-subject/export?email=subject@example.test"},
		{http.MethodPost, "/api/v1/billing/checkout"},
		{http.MethodPost, "/api/v1/billing/cancel"},
	} {
		if got := authorizedRouteStatus(t, "viewer", test.method, test.path); got != http.StatusForbidden {
			t.Errorf("viewer %s %s = %d, want 403", test.method, test.path, got)
		}
	}
}

func TestBillingMutationRequiresOwner(t *testing.T) {
	for _, path := range []string{"/api/v1/billing/checkout", "/api/v1/billing/cancel"} {
		if got := authorizedRouteStatus(t, "sender", http.MethodPost, path); got != http.StatusForbidden {
			t.Errorf("sender POST %s = %d, want 403", path, got)
		}
	}
}
