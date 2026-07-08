// Package qes implements v1.1 Qualified Electronic Signature routing.
//
// When a document's routing_tier is QES (Phase 9 eIDAS escalation), the
// signer is redirected to a QTSP (Idura BankID, Signicat, Scrive)
// instead of the typed-name+ed25519 flow. The QTSP performs the actual
// signature using a Qualified Certificate chained to an eIDAS trusted
// root list (Article 26 + Article 32). We persist the resulting identity
// assertion + signature in qes_signing_sessions so the audit cert + the
// Phase 10.2 evidence bundle can reproduce the chain for forensic
// review.
//
// This package exposes a single Provider interface so swapping QTSPs is
// a one-line registry change. NoopProvider rejects every request (used
// when QES is disabled). MockProvider auto-completes (used in dev +
// e2e). IduraProvider hits the live Idura REST API.
package qes

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Session is the engine-side view of a qes_signing_sessions row. The
// engine stays decoupled from sqlc so unit tests can construct sessions
// without a database.
type Session struct {
	ID                uuid.UUID
	DocumentID        uuid.UUID
	RecipientID       uuid.UUID
	OrgID             uuid.UUID
	Provider          string
	ProviderSessionID string
	Status            string
	RedirectURL       string
	CallbackSecret    string
	CompletedAt       *time.Time
	ExpiresAt         time.Time
}

// StartInput is what the engine hands a Provider when starting a
// signature challenge. CallbackURL is where the QTSP should redirect the
// signer after they complete (or cancel) the challenge.
type StartInput struct {
	DocumentID     uuid.UUID
	RecipientID    uuid.UUID
	RecipientEmail string
	RecipientName  string
	CallbackURL    string
	// SignedDigest is the SHA-256 of the document body bytes that the
	// QTSP should bind its signature to. The QTSP MUST sign over this
	// digest so the resulting signature is provably about THIS document.
	SignedDigest [32]byte
}

// StartResult is what a Provider returns. ProviderSessionID is the
// QTSP's own session handle (used to correlate the callback);
// RedirectURL is where to send the signer's browser.
type StartResult struct {
	ProviderSessionID string
	RedirectURL       string
	// CallbackSecret is a per-session shared secret the engine uses to
	// HMAC-verify the QTSP callback so we don't blindly trust a request
	// that just happens to hit /qes/callback with the right session ID.
	CallbackSecret string
	ExpiresAt      time.Time
}

// CallbackInput is what the engine hands the Provider when the QTSP
// posts back. RawBody is the unparsed payload (so the Provider can
// HMAC-verify it against CallbackSecret); ProviderSessionID names the
// session being completed.
type CallbackInput struct {
	ProviderSessionID string
	CallbackSecret    string
	RawBody           []byte
	Headers           map[string]string
}

// CallbackResult carries the validated, persisted shape of the
// signature: the canonical identity assertion JSON, the detached
// signature (base64), and the cert chain PEM bytes.
type CallbackResult struct {
	IdentityAssertion []byte // canonical JSON; persisted to qes_signing_sessions.identity_assertion_json
	SignatureB64      string
	CertChainPEM      string
	SignerName        string // human-readable, surfaced on the audit cert
	SignerSerial      string // personnummer or QTSP serial; treat as PII
}

// Provider is the strategy interface. Implementations live below.
type Provider interface {
	// Name returns the canonical provider key persisted in
	// qes_signing_sessions.provider ('mock' | 'idura' | 'signicat').
	Name() string
	Start(ctx context.Context, in StartInput) (*StartResult, error)
	Callback(ctx context.Context, in CallbackInput) (*CallbackResult, error)
}

// Errors surfaced to handlers. Each is a sentinel so callers can match
// with errors.Is and route to the right HTTP status code.
var (
	ErrDisabled        = errors.New("qes: feature disabled on this instance")
	ErrProviderUnknown = errors.New("qes: unknown provider")
	ErrInvalidCallback = errors.New("qes: callback signature mismatch")
	ErrSessionExpired  = errors.New("qes: session expired")
)

// NoopProvider rejects every request. Wired when HASH_QES_PROVIDER is
// empty AND the feature flag is off. Lets the surface still compile +
// route correctly without forcing dev to set up a real QTSP.
type NoopProvider struct{}

func (NoopProvider) Name() string                                            { return "noop" }
func (NoopProvider) Start(context.Context, StartInput) (*StartResult, error) { return nil, ErrDisabled }
func (NoopProvider) Callback(context.Context, CallbackInput) (*CallbackResult, error) {
	return nil, ErrDisabled
}

// MockProvider auto-completes every signing challenge with a synthetic
// identity assertion. Used for laptop dev, Playwright e2e, and the
// initial production cutover before live Idura creds land.
type MockProvider struct {
	// IssuedAt is overridable so tests are deterministic.
	IssuedAt time.Time
	// MockSignerName + MockSignerSerial appear in the synthetic
	// identity assertion. Empty falls back to defaults that look
	// realistic-but-obviously-fake ("MOCK QES SIGNER").
	MockSignerName   string
	MockSignerSerial string
}

func (MockProvider) Name() string { return "mock" }

func (p MockProvider) Start(_ context.Context, in StartInput) (*StartResult, error) {
	pid, err := randomToken(16)
	if err != nil {
		return nil, err
	}
	secret, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	now := p.IssuedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return &StartResult{
		ProviderSessionID: "mock-" + pid,
		// In the mock flow we redirect right back to the callback so
		// the signer page transitions to "completed" in one click.
		// In a real provider this would be the QTSP's hosted UI.
		RedirectURL:    in.CallbackURL + "?mock=1",
		CallbackSecret: secret,
		ExpiresAt:      now.Add(1 * time.Hour),
	}, nil
}

func (p MockProvider) Callback(_ context.Context, in CallbackInput) (*CallbackResult, error) {
	name := p.MockSignerName
	if name == "" {
		name = "MOCK QES SIGNER"
	}
	serial := p.MockSignerSerial
	if serial == "" {
		serial = "19000101-0000"
	}
	assertion := []byte(`{"provider":"mock","level":"QES","name":"` + name + `","serial":"` + serial + `","issued_at":"` + time.Now().UTC().Format(time.RFC3339) + `","note":"DEVELOPMENT ONLY - this assertion was issued by the MockProvider and is NOT a real QES."}`)
	sigSeed, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	return &CallbackResult{
		IdentityAssertion: assertion,
		SignatureB64:      base64.StdEncoding.EncodeToString([]byte("mock-" + sigSeed)),
		CertChainPEM:      "-----BEGIN MOCK QES CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString([]byte("mock-cert-"+sigSeed)) + "\n-----END MOCK QES CERTIFICATE-----\n",
		SignerName:        name,
		SignerSerial:      serial,
	}, nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// nowUnix returns the current Unix timestamp in seconds. Wrapped so tests
// inside the package can monkey-patch the clock when needed.
func nowUnix() int64 {
	return time.Now().UTC().Unix()
}
