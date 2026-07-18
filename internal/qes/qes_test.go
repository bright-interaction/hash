// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package qes

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestMockProvider_StartReturnsRedirectAndSecret(t *testing.T) {
	p := MockProvider{}
	res, err := p.Start(context.Background(), StartInput{
		DocumentID:     uuid.New(),
		RecipientID:    uuid.New(),
		RecipientEmail: "signer@example.com",
		RecipientName:  "Signer",
		CallbackURL:    "https://hash.example/qes/callback/__session__",
		SignedDigest:   [32]byte{1, 2, 3},
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !strings.HasPrefix(res.ProviderSessionID, "mock-") {
		t.Errorf("expected mock- prefix, got %q", res.ProviderSessionID)
	}
	if res.RedirectURL == "" {
		t.Error("redirect_url empty")
	}
	if len(res.CallbackSecret) < 16 {
		t.Errorf("callback secret too short: %d", len(res.CallbackSecret))
	}
	if res.ExpiresAt.IsZero() {
		t.Error("expires_at zero")
	}
}

func TestMockProvider_CallbackSyntheticAssertion(t *testing.T) {
	p := MockProvider{MockSignerName: "Test Signer", MockSignerSerial: "19800101-1234"}
	out, err := p.Callback(context.Background(), CallbackInput{
		ProviderSessionID: "mock-abc",
		CallbackSecret:    "secret",
		RawBody:           []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if out.SignerName != "Test Signer" {
		t.Errorf("signer name = %q", out.SignerName)
	}
	if out.SignerSerial != "19800101-1234" {
		t.Errorf("signer serial = %q", out.SignerSerial)
	}
	var assertion struct {
		Provider string `json:"provider"`
		Level    string `json:"level"`
		Name     string `json:"name"`
	}
	if err := json.Unmarshal(out.IdentityAssertion, &assertion); err != nil {
		t.Fatalf("identity_assertion not parseable JSON: %v", err)
	}
	if assertion.Provider != "mock" || assertion.Level != "QES" {
		t.Errorf("assertion wrong: %#v", assertion)
	}
	if out.SignatureB64 == "" {
		t.Error("signature_b64 empty")
	}
	if !strings.Contains(out.CertChainPEM, "BEGIN MOCK QES CERTIFICATE") {
		t.Error("cert chain pem missing marker")
	}
}

func TestNoopProvider_RejectsEverything(t *testing.T) {
	p := NoopProvider{}
	if _, err := p.Start(context.Background(), StartInput{}); !errors.Is(err, ErrDisabled) {
		t.Errorf("expected ErrDisabled on Start, got %v", err)
	}
	if _, err := p.Callback(context.Background(), CallbackInput{}); !errors.Is(err, ErrDisabled) {
		t.Errorf("expected ErrDisabled on Callback, got %v", err)
	}
	if p.Name() != "noop" {
		t.Errorf("name = %q", p.Name())
	}
}

func TestIduraProvider_CallbackHMACValidation(t *testing.T) {
	p := &IduraProvider{}
	body := []byte(`{"session_id":"abc","status":"completed","signature_b64":"sig","cert_chain_pem":"pem","signer_name":"Test","signer_serial":"x"}`)
	secret := "callback-secret-abc"

	ts := nowUnixMinus(60) // 1 minute in the past, well within the skew window
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "t=%d.", ts)
	mac.Write(body)
	hexSig := hex.EncodeToString(mac.Sum(nil))
	headers := map[string]string{
		"X-Idura-Signature": fmt.Sprintf("t=%d,v1=%s", ts, hexSig),
	}
	res, err := p.Callback(context.Background(), CallbackInput{
		ProviderSessionID: "abc",
		CallbackSecret:    secret,
		RawBody:           body,
		Headers:           headers,
	})
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	if res.SignatureB64 != "sig" || res.SignerName != "Test" {
		t.Errorf("decoded fields wrong: %#v", res)
	}
}

func TestIduraProvider_CallbackRejectsMissingHeader(t *testing.T) {
	p := &IduraProvider{}
	_, err := p.Callback(context.Background(), CallbackInput{
		ProviderSessionID: "abc",
		CallbackSecret:    "secret",
		RawBody:           []byte(`{}`),
		Headers:           map[string]string{},
	})
	if !errors.Is(err, ErrInvalidCallback) {
		t.Errorf("expected ErrInvalidCallback, got %v", err)
	}
}

func TestIduraProvider_CallbackRejectsBadHMAC(t *testing.T) {
	p := &IduraProvider{}
	body := []byte(`{"session_id":"abc","status":"completed"}`)
	ts := nowUnixMinus(60)
	headers := map[string]string{
		"X-Idura-Signature": fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString([]byte("deadbeefdeadbeefdeadbeefdeadbeef"))),
	}
	_, err := p.Callback(context.Background(), CallbackInput{
		ProviderSessionID: "abc",
		CallbackSecret:    "secret",
		RawBody:           body,
		Headers:           headers,
	})
	if !errors.Is(err, ErrInvalidCallback) {
		t.Errorf("expected ErrInvalidCallback on hmac mismatch, got %v", err)
	}
}

func TestIduraProvider_CallbackRejectsStaleTimestamp(t *testing.T) {
	p := &IduraProvider{}
	body := []byte(`{}`)
	secret := "secret"
	ts := nowUnixMinus(60 * 60) // 1 hour stale, outside the 10-min skew window
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "t=%d.", ts)
	mac.Write(body)
	hexSig := hex.EncodeToString(mac.Sum(nil))
	headers := map[string]string{
		"X-Idura-Signature": fmt.Sprintf("t=%d,v1=%s", ts, hexSig),
	}
	_, err := p.Callback(context.Background(), CallbackInput{
		CallbackSecret: secret,
		RawBody:        body,
		Headers:        headers,
	})
	if !errors.Is(err, ErrInvalidCallback) {
		t.Errorf("expected ErrInvalidCallback on stale ts, got %v", err)
	}
}

func TestIduraProvider_CallbackRejectsNonCompletedStatus(t *testing.T) {
	p := &IduraProvider{}
	body := []byte(`{"session_id":"abc","status":"failed","failure_reason":"user cancelled"}`)
	secret := "secret"
	ts := nowUnixMinus(60)
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "t=%d.", ts)
	mac.Write(body)
	hexSig := hex.EncodeToString(mac.Sum(nil))
	headers := map[string]string{
		"X-Idura-Signature": fmt.Sprintf("t=%d,v1=%s", ts, hexSig),
	}
	_, err := p.Callback(context.Background(), CallbackInput{
		CallbackSecret: secret,
		RawBody:        body,
		Headers:        headers,
	})
	if err == nil {
		t.Fatal("expected error for non-completed status")
	}
	if !strings.Contains(err.Error(), "user cancelled") {
		t.Errorf("expected failure_reason in error, got %v", err)
	}
}

func TestParseSignatureHeader(t *testing.T) {
	ts, hexSig, err := parseSignatureHeader("t=1700000000,v1=abc123")
	if err != nil {
		t.Fatal(err)
	}
	if ts != 1700000000 || hexSig != "abc123" {
		t.Errorf("parse wrong: ts=%d sig=%q", ts, hexSig)
	}
	if _, _, err := parseSignatureHeader("malformed"); err == nil {
		t.Error("expected error on malformed header")
	}
}

// helpers

func nowUnixMinus(secondsAgo int64) int64 {
	return nowUnix() - secondsAgo
}
