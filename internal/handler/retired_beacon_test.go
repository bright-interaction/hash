// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRetiredOpenBeaconIsStaticAndNonRecording(t *testing.T) {
	server := &Server{} // no signer, database, or audit dependency by design
	recorder := httptest.NewRecorder()
	server.handleRetiredOpenBeacon(recorder, httptest.NewRequest(http.MethodGet, "/e/o/recipient-token", nil))
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "image/gif" {
		t.Fatalf("legacy pixel response = %d %q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	if recorder.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("legacy pixel should be cacheable and non-tracking: %q", recorder.Header().Get("Cache-Control"))
	}
}
