// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/resolver"
)

// newNilAuditLogger returns an audit.Logger that short-circuits any Log
// call because the brightcrm-inbound handler always emits with OrgID =
// uuid.Nil. The Logger never touches its (nil) DB handle in that branch.
func newNilAuditLogger() *audit.Logger { return audit.New(nil, nil) }

// newBrightCRMTestServer builds a minimal Server wired with just the bits
// the brightcrm webhook handler touches. Audit is wired with nil Queries
// because the handler always emits with OrgID = uuid.Nil, which short-
// circuits before any DB call.
func newBrightCRMTestServer(secret, publicURL string) *Server {
	return &Server{
		Resolver:               resolver.New(nil),
		BrightCRMWebhookSecret: secret,
		PublicURL:              publicURL,
		Audit:                  newNilAuditLogger(),
	}
}

func postBrightCRM(t *testing.T, s *Server, body, sigHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhooks/brightcrm", strings.NewReader(body))
	if sigHeader != "" {
		req.Header.Set("X-BrightCRM-Signature", sigHeader)
	}
	rr := httptest.NewRecorder()
	s.handleBrightCRMWebhook(rr, req)
	return rr
}

func signedBrightCRMBody(secret, body string, now time.Time) (string, string) {
	tsStr := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("t=" + tsStr + "."))
	mac.Write([]byte(body))
	sig := hex.EncodeToString(mac.Sum(nil))
	return body, "t=" + tsStr + ",v1=" + sig
}

func TestBrightCRMWebhook_FailsClosedInProdWithoutSecret(t *testing.T) {
	s := newBrightCRMTestServer("", "https://hash.brightinteraction.com")
	rr := postBrightCRM(t, s, `{"event":"deal.updated","data":{"id":"deal_1"}}`, "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing secret in prod should 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestBrightCRMWebhook_AcceptsLocalDevWithoutSecret(t *testing.T) {
	s := newBrightCRMTestServer("", "http://localhost:8090")
	rr := postBrightCRM(t, s, `{"event":"deal.updated","data":{"id":"deal_1"}}`, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("local dev should accept unsigned event, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestBrightCRMWebhook_RejectsBadSignatureInProd(t *testing.T) {
	s := newBrightCRMTestServer("supersecretsecretsecretsecretsecret", "https://hash.brightinteraction.com")
	body, _ := signedBrightCRMBody("wrong-secret", `{"event":"deal.updated","data":{"id":"deal_2"}}`, time.Now())
	rr := postBrightCRM(t, s, body, "t="+strconv.FormatInt(time.Now().Unix(), 10)+",v1=deadbeef")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("forged signature should 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestBrightCRMWebhook_AcceptsValidSignatureInProd(t *testing.T) {
	secret := "supersecretsecretsecretsecretsecret"
	s := newBrightCRMTestServer(secret, "https://hash.brightinteraction.com")
	body, header := signedBrightCRMBody(secret, `{"event":"deal.updated","data":{"id":"deal_3"}}`, time.Now())
	rr := postBrightCRM(t, s, body, header)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid signature should 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestVerifyBrightCRMSignature_HappyPath(t *testing.T) {
	secret := "test-secret"
	body := []byte(`{"event":"deal.updated","data":{"id":"deal_x"}}`)
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	tsStr := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("t=" + tsStr + "."))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))
	header := "t=" + tsStr + ",v1=" + sig
	if err := verifyBrightCRMSignature(header, secret, body, now); err != nil {
		t.Fatalf("happy path: %v", err)
	}
}

func TestVerifyBrightCRMSignature_BadSignature(t *testing.T) {
	now := time.Now()
	header := "t=" + strconv.FormatInt(now.Unix(), 10) + ",v1=deadbeef"
	if err := verifyBrightCRMSignature(header, "secret", []byte("body"), now); err == nil {
		t.Fatal("should reject bad signature")
	}
}

func TestVerifyBrightCRMSignature_StaleTimestamp(t *testing.T) {
	secret := "test"
	body := []byte("x")
	stale := time.Now().Add(-10 * time.Minute)
	tsStr := strconv.FormatInt(stale.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("t=" + tsStr + "."))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))
	header := "t=" + tsStr + ",v1=" + sig
	if err := verifyBrightCRMSignature(header, secret, body, time.Now()); err == nil {
		t.Fatal("should reject 10-min-old timestamp (skew window is 5 min)")
	}
}

func TestVerifyBrightCRMSignature_MissingHeader(t *testing.T) {
	if err := verifyBrightCRMSignature("", "secret", []byte("x"), time.Now()); err == nil {
		t.Fatal("missing header should error")
	}
}

func TestMapBrightCRMEvent(t *testing.T) {
	cases := map[string]string{
		"deal.updated":    "crm.deal",
		"deal.created":    "crm.deal",
		"deal.deleted":    "crm.deal",
		"contact.updated": "crm.contact",
		"contact.created": "crm.contact",
		"random.event":    "",
		"":                "",
	}
	for in, want := range cases {
		if got := mapBrightCRMEventToSourceKind(in); got != want {
			t.Errorf("%q -> got %q want %q", in, got, want)
		}
	}
}
