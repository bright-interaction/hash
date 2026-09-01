// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/resolver"
)

var brightCRMTestOrgID = uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")

type fakeBrightCRMProcessor struct {
	result brightCRMWebhookProcessResult
	err    error
	calls  []brightCRMWebhookProcessInput
}

func (f *fakeBrightCRMProcessor) processBrightCRMWebhook(_ context.Context, input brightCRMWebhookProcessInput) (brightCRMWebhookProcessResult, error) {
	f.calls = append(f.calls, input)
	if f.err != nil {
		return brightCRMWebhookProcessResult{}, f.err
	}
	return f.result, nil
}

// newBrightCRMTestServer builds a minimal Server wired with just the bits
// the brightcrm webhook handler touches.
func newBrightCRMTestServer(secret, publicURL string) *Server {
	return &Server{
		Resolver:               resolver.New(nil),
		BrightCRMWebhookSecret: secret,
		PublicURL:              publicURL,
		brightCRMProcessorOverride: &fakeBrightCRMProcessor{
			result: brightCRMWebhookProcessResult{OrgIDs: []uuid.UUID{brightCRMTestOrgID}},
		},
	}
}

func postBrightCRM(t *testing.T, s *Server, body, sigHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhooks/brightcrm", strings.NewReader(body))
	if sigHeader != "" {
		req.Header.Set("X-BrightCRM-Signature", sigHeader)
	}
	var envelope brightCRMEvent
	if json.Unmarshal([]byte(body), &envelope) == nil && envelope.ID != "" {
		req.Header.Set(brightCRMDeliveryIDHeader, envelope.ID)
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

func currentBrightCRMSignature(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestBrightCRMWebhook_FailsClosedInProdWithoutSecret(t *testing.T) {
	s := newBrightCRMTestServer("", "https://hash.brightinteraction.com")
	rr := postBrightCRM(t, s, `{"id":"wh_missing_secret","event":"deal.updated","data":{"id":"deal_1"}}`, "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing secret in prod should 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestBrightCRMWebhook_FailsClosedInLocalDevWithoutSecret(t *testing.T) {
	s := newBrightCRMTestServer("", "http://localhost:8090")
	rr := postBrightCRM(t, s, `{"id":"wh_missing_secret","event":"deal.updated","data":{"id":"deal_1"}}`, "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("active local receiver without secret should 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestBrightCRMWebhook_DisabledResolverAcknowledgesWithoutSecret(t *testing.T) {
	s := newBrightCRMTestServer("", "http://localhost:8090")
	s.Resolver = nil
	rr := postBrightCRM(t, s, `{"id":"wh_disabled","event":"deal.updated","data":{"id":"deal_1"}}`, "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("disabled receiver should remain a no-op, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestBrightCRMWebhook_RejectsBadSignatureInProd(t *testing.T) {
	s := newBrightCRMTestServer("supersecretsecretsecretsecretsecret", "https://hash.brightinteraction.com")
	body, _ := signedBrightCRMBody("wrong-secret", `{"id":"wh_bad_signature","event":"deal.updated","data":{"id":"deal_2"}}`, time.Now())
	rr := postBrightCRM(t, s, body, "t="+strconv.FormatInt(time.Now().Unix(), 10)+",v1=deadbeef")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("forged signature should 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestBrightCRMWebhook_AcceptsValidSignatureInProd(t *testing.T) {
	secret := "supersecretsecretsecretsecretsecret"
	s := newBrightCRMTestServer(secret, "https://hash.brightinteraction.com")
	body := `{"id":"wh_current_dispatcher","event":"DEAL_UPDATED","data":{"id":"deal_3-sensitive"}}`
	header := currentBrightCRMSignature(secret, body)
	rr := postBrightCRM(t, s, body, header)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid signature should 200, got %d: %s", rr.Code, rr.Body.String())
	}
	processor := s.brightCRMProcessorOverride.(*fakeBrightCRMProcessor)
	if len(processor.calls) != 1 || processor.calls[0].SourceKind != "crm.deal" || processor.calls[0].SourceRef != "deal_3-sensitive" {
		t.Fatalf("unexpected processor call: %#v", processor.calls)
	}
	entryPayload := processor.calls[0].AuditPayload
	for _, forbidden := range []string{"source_ref", "source_ref_sha256", "body_sha256"} {
		if _, leaked := entryPayload[forbidden]; leaked {
			t.Fatalf("unkeyed or raw BrightCRM field %q must not enter the long-lived audit payload", forbidden)
		}
	}
	digest, ok := entryPayload["source_ref_correlation"].(string)
	if !ok || len(digest) != sha256.Size*2 || strings.Contains(digest, "deal_3-sensitive") {
		t.Fatalf("source reference correlation token is not canonical HMAC-SHA-256 hex: %#v", entryPayload["source_ref_correlation"])
	}
	if digest == brightCRMAuditCorrelation("different-secret", "source-ref", []byte("crm.deal\x00deal_3-sensitive")) {
		t.Fatal("source correlation token did not depend on the configured webhook secret")
	}
}

func TestBrightCRMWebhook_AcceptsSignedBodyDeliveryIDWithoutRedundantHeader(t *testing.T) {
	secret := "supersecretsecretsecretsecretsecret"
	s := newBrightCRMTestServer(secret, "https://hash.brightinteraction.com")
	body := `{"id":"wh_legacy_async","event":"DEAL_UPDATED","data":{"id":"deal_legacy"}}`
	req := httptest.NewRequest(http.MethodPost, "/webhooks/brightcrm", strings.NewReader(body))
	req.Header.Set(brightCRMSignatureHeader, currentBrightCRMSignature(secret, body))
	rr := httptest.NewRecorder()
	s.handleBrightCRMWebhook(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("signed body delivery id should interoperate without redundant header, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestBrightCRMWebhook_RejectsMismatchedDeliveryHeader(t *testing.T) {
	secret := "supersecretsecretsecretsecretsecret"
	s := newBrightCRMTestServer(secret, "https://hash.brightinteraction.com")
	body := `{"id":"wh_signed_body","event":"DEAL_UPDATED","data":{"id":"deal_legacy"}}`
	req := httptest.NewRequest(http.MethodPost, "/webhooks/brightcrm", strings.NewReader(body))
	req.Header.Set(brightCRMSignatureHeader, currentBrightCRMSignature(secret, body))
	req.Header.Set(brightCRMDeliveryIDHeader, "wh_different_header")
	rr := httptest.NewRecorder()
	s.handleBrightCRMWebhook(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("mismatched delivery header should be rejected, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestBrightCRMAuditCorrelationIsDomainSeparatedAndKeyed(t *testing.T) {
	value := []byte("small-guessable-id")
	base := brightCRMAuditCorrelation("secret-a", "source-ref", value)
	if len(base) != sha256.Size*2 {
		t.Fatalf("correlation token length = %d, want %d", len(base), sha256.Size*2)
	}
	if base == brightCRMAuditCorrelation("secret-b", "source-ref", value) {
		t.Fatal("correlation token is not keyed")
	}
	if base == brightCRMAuditCorrelation("secret-a", "body", value) {
		t.Fatal("correlation token domains collide")
	}
}

func TestBrightCRMWebhook_FailsClosedWithoutDurableAuditDependencies(t *testing.T) {
	secret := "supersecretsecretsecretsecretsecret"
	s := newBrightCRMTestServer(secret, "https://hash.brightinteraction.com")
	s.brightCRMProcessorOverride = nil
	body, header := signedBrightCRMBody(secret, `{"id":"wh_missing_deps","event":"deal.updated","data":{"id":"deal_4"}}`, time.Now())
	rr := postBrightCRM(t, s, body, header)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing durable audit dependencies should 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestBrightCRMWebhook_FailsClosedWhenTenantLookupFails(t *testing.T) {
	secret := "supersecretsecretsecretsecretsecret"
	s := newBrightCRMTestServer(secret, "https://hash.brightinteraction.com")
	processor := &fakeBrightCRMProcessor{err: errors.New("database unavailable")}
	s.brightCRMProcessorOverride = processor
	body, header := signedBrightCRMBody(secret, `{"id":"wh_lookup_failure","event":"deal.updated","data":{"id":"deal_5"}}`, time.Now())
	rr := postBrightCRM(t, s, body, header)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed tenant lookup should 503, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := len(processor.calls); got != 1 {
		t.Fatalf("processor calls after failure = %d, want 1", got)
	}
}

func TestBrightCRMWebhook_FailsClosedWhenAuditWriteFails(t *testing.T) {
	secret := "supersecretsecretsecretsecretsecret"
	s := newBrightCRMTestServer(secret, "https://hash.brightinteraction.com")
	s.brightCRMProcessorOverride = &fakeBrightCRMProcessor{err: errors.New("audit unavailable")}
	body, header := signedBrightCRMBody(secret, `{"id":"wh_audit_failure","event":"contact.updated","data":{"id":"contact_1"}}`, time.Now())
	rr := postBrightCRM(t, s, body, header)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed audit write should 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestBrightCRMWebhook_RejectsDeliveryIDContentCollisionPermanently(t *testing.T) {
	secret := "supersecretsecretsecretsecretsecret"
	s := newBrightCRMTestServer(secret, "https://hash.brightinteraction.com")
	s.brightCRMProcessorOverride = &fakeBrightCRMProcessor{err: errBrightCRMDeliveryConflict}
	body := `{"id":"wh_collision","event":"contact.updated","data":{"id":"contact_1"}}`
	rr := postBrightCRM(t, s, body, currentBrightCRMSignature(secret, body))
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("delivery id content collision should be a permanent 422, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestBrightCRMWebhook_ZeroAffectedOrgsIsNoOp(t *testing.T) {
	secret := "supersecretsecretsecretsecretsecret"
	s := newBrightCRMTestServer(secret, "https://hash.brightinteraction.com")
	processor := &fakeBrightCRMProcessor{result: brightCRMWebhookProcessResult{OrgIDs: []uuid.UUID{}}}
	s.brightCRMProcessorOverride = processor
	body, header := signedBrightCRMBody(secret, `{"id":"wh_zero_org","event":"deal.deleted","data":{"id":"absent"}}`, time.Now())
	rr := postBrightCRM(t, s, body, header)
	if rr.Code != http.StatusOK {
		t.Fatalf("zero-org no-op should 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := len(processor.calls); got != 1 {
		t.Fatalf("processor calls for zero-org no-op = %d, want 1", got)
	}
	if !strings.Contains(rr.Body.String(), `"invalidated_count":0`) {
		t.Fatalf("zero-org response must report no invalidation: %s", rr.Body.String())
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

func TestVerifyBrightCRMSignature_CurrentDispatcherProtocol(t *testing.T) {
	secret := "test-secret"
	body := []byte(`{"id":"wh_current","event":"DEAL_UPDATED","data":{"id":"deal_x"}}`)
	if err := verifyBrightCRMSignature(currentBrightCRMSignature(secret, string(body)), secret, body, time.Now()); err != nil {
		t.Fatalf("current BrightCRM signature: %v", err)
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
		"DEAL_UPDATED":    "crm.deal",
		"CONTACT_UPDATED": "crm.contact",
		"random.event":    "",
		"":                "",
	}
	for in, want := range cases {
		if got := mapBrightCRMEventToSourceKind(in); got != want {
			t.Errorf("%q -> got %q want %q", in, got, want)
		}
	}
}
