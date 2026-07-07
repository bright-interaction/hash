package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func ctxRole(role string) context.Context {
	if role == "" {
		return context.Background()
	}
	return context.WithValue(context.Background(), RoleKey, role)
}

func TestRoleAtLeast(t *testing.T) {
	cases := []struct {
		role string
		min  Role
		want bool
	}{
		{"owner", RoleOwner, true},
		{"owner", RoleSender, true},
		{"owner", RoleViewer, true},
		{"sender", RoleOwner, false},
		{"sender", RoleSender, true},
		{"sender", RoleViewer, true},
		{"viewer", RoleSender, false},
		{"viewer", RoleViewer, true},
		{"", RoleViewer, false},      // unset ranks below viewer (fail-closed)
		{"bogus", RoleViewer, false}, // unknown role too
	}
	for _, c := range cases {
		if got := RoleAtLeast(ctxRole(c.role), c.min); got != c.want {
			t.Errorf("RoleAtLeast(role=%q, min=%q) = %v, want %v", c.role, c.min, got, c.want)
		}
	}
}

func serve(mw func(http.Handler) http.Handler, method, role string) int {
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(method, "/x", nil).WithContext(ctxRole(role))
	h.ServeHTTP(rr, req)
	return rr.Code
}

func TestRequireRole(t *testing.T) {
	mw := RequireRole(RoleOwner)
	if got := serve(mw, http.MethodGet, "owner"); got != http.StatusOK {
		t.Errorf("owner GET = %d, want 200", got)
	}
	if got := serve(mw, http.MethodGet, "sender"); got != http.StatusForbidden {
		t.Errorf("sender GET = %d, want 403", got)
	}
	if got := serve(mw, http.MethodPost, "viewer"); got != http.StatusForbidden {
		t.Errorf("viewer POST = %d, want 403", got)
	}
}

func TestRequireRoleForWrites(t *testing.T) {
	mw := RequireRoleForWrites(RoleSender)
	// Reads pass for everyone, including viewers.
	if got := serve(mw, http.MethodGet, "viewer"); got != http.StatusOK {
		t.Errorf("viewer GET = %d, want 200", got)
	}
	// Writes need sender+.
	if got := serve(mw, http.MethodPost, "viewer"); got != http.StatusForbidden {
		t.Errorf("viewer POST = %d, want 403", got)
	}
	if got := serve(mw, http.MethodPost, "sender"); got != http.StatusOK {
		t.Errorf("sender POST = %d, want 200", got)
	}
	if got := serve(mw, http.MethodDelete, "owner"); got != http.StatusOK {
		t.Errorf("owner DELETE = %d, want 200", got)
	}
}
