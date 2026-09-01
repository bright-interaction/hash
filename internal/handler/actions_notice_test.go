// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLegacyEmailCommentReplyRoutesAreNonMutatingTombstones(t *testing.T) {
	server := &Server{}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(method, "/a/comment?t=legacy-token", strings.NewReader("body=bypass"))
		if method == http.MethodGet {
			server.handleCommentReplyPage(recorder, request)
		} else {
			server.handleCommentReplyConfirm(recorder, request)
		}
		if recorder.Code != http.StatusGone {
			t.Fatalf("%s status = %d, want %d", method, recorder.Code, http.StatusGone)
		}
		if !strings.Contains(recorder.Body.String(), "current privacy notice") || strings.Contains(recorder.Body.String(), "<form") {
			t.Fatalf("%s tombstone body = %q", method, recorder.Body.String())
		}
	}
}
