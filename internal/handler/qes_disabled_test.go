// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bright-interaction/hash/internal/sign"
)

func TestQESLifecycleHandlersFailClosed(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		name   string
		method string
		call   func(http.ResponseWriter, *http.Request)
	}{
		{name: "start", method: http.MethodPost, call: s.handleQESStart},
		{name: "status", method: http.MethodGet, call: s.handleQESStatus},
		{name: "callback", method: http.MethodPost, call: s.handleQESCallback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, "http://localhost/qes", nil)
			tc.call(rr, req)
			if rr.Code != http.StatusGone {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusGone, rr.Body.String())
			}
			if got := rr.Body.String(); got == "" {
				t.Fatal("fail-closed response must explain that QES is unavailable")
			}
		})
	}
}

func TestQESLifecycleRoutesAreExplicitGoneTombstones(t *testing.T) {
	h := (&Server{Sign: &sign.Engine{}}).Routes()
	for _, tc := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/qes/callback/provider-session"},
		{method: http.MethodPost, path: "/sign/legacy-token/qes/start"},
		{method: http.MethodGet, path: "/sign/legacy-token/qes/status"},
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, nil))
		if rr.Code != http.StatusGone {
			t.Errorf("%s %s status = %d, want %d; body=%s", tc.method, tc.path, rr.Code, http.StatusGone, rr.Body.String())
		}
	}
}
