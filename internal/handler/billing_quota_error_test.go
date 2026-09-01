// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/billing"
)

func TestWriteSendErrorEntitlementUnavailableIsRetryable503(t *testing.T) {
	recorder := httptest.NewRecorder()
	(&Server{}).writeSendError(recorder, &billing.EntitlementUnavailableError{
		Stage: "load usage", Err: errors.New("database unavailable"),
	})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "database unavailable") || strings.Contains(recorder.Body.String(), "upgrade_url") {
		t.Fatalf("503 leaked internal cause or advertised an upgrade: %s", recorder.Body.String())
	}
}

func TestWriteAuthoringQuotaErrorMapsKnownQuotaToPaymentRequired(t *testing.T) {
	recorder := httptest.NewRecorder()
	err := errors.Join(billing.ErrQuotaExceeded, errors.New("plan free allows 5 documents"))
	if !(&Server{}).writeAuthoringQuotaError(recorder, err) {
		t.Fatal("known quota error was not handled")
	}
	if recorder.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402; body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"upgrade_url":"/settings/billing"`) {
		t.Fatalf("quota response omitted upgrade URL: %s", recorder.Body.String())
	}
}

func TestWriteAuthoringQuotaErrorHidesEntitlementCause(t *testing.T) {
	recorder := httptest.NewRecorder()
	err := &billing.EntitlementUnavailableError{
		Stage: "lock quota mutation", Err: errors.New("postgres host=secret.internal"),
	}
	if !(&Server{}).writeAuthoringQuotaError(recorder, err) {
		t.Fatal("entitlement outage was not handled")
	}
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "postgres") || strings.Contains(recorder.Body.String(), "secret.internal") || strings.Contains(recorder.Body.String(), "upgrade_url") {
		t.Fatalf("503 leaked internal cause or advertised an upgrade: %s", recorder.Body.String())
	}
}

func TestWriteAuthoringQuotaErrorDeclinesUnexpectedFailure(t *testing.T) {
	recorder := httptest.NewRecorder()
	if (&Server{}).writeAuthoringQuotaError(recorder, errors.New("unexpected")) {
		t.Fatal("unexpected failure was misclassified as a quota response")
	}
	if recorder.Code != http.StatusOK || recorder.Body.Len() != 0 {
		t.Fatalf("declined error wrote a response: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
