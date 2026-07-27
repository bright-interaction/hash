// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/nethard"
)

// ValidateWebhookURL guards the webhook delivery path against SSRF. The
// delivery URL is tenant-controlled, so a URL pointing at an internal or
// cloud-metadata address would let a tenant reach services behind the firewall
// and exfiltrate the (logged) response. Production requires https and rejects
// URLs that resolve to a private/loopback/link-local/unspecified address.
// allowPrivate=true (local dev) relaxes this so e2e receivers on localhost work.
func ValidateWebhookURL(raw string, allowPrivate bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return errors.New("invalid webhook url")
	}
	if u.Scheme != "https" && !(allowPrivate && u.Scheme == "http") {
		return errors.New("webhook url must be https")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("webhook url has no host")
	}
	if allowPrivate {
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return errors.New("webhook host does not resolve")
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
			return errors.New("webhook url resolves to a disallowed (private/loopback/link-local) address")
		}
	}
	return nil
}

// WebhookEvent is the JSON shape Hash posts to subscriber URLs. Mirrors
// the brightcrm + atomicsite payload shape so existing receivers can be
// repointed at us with minimal code changes.
type WebhookEvent struct {
	EventID    string         `json:"event_id"`
	Kind       string         `json:"kind"`
	OccurredAt time.Time      `json:"occurred_at"`
	OrgID      string         `json:"org_id"`
	Document   map[string]any `json:"document,omitempty"`
	Recipient  map[string]any `json:"recipient,omitempty"`
	Payload    map[string]any `json:"payload,omitempty"`
}

// SignaturePair holds the secret pair the rotation engine writes to us.
// Sign uses Primary; verify (on the receiver side) accepts either Primary
// or Previous so a rotation grace window is non-disruptive.
type SignaturePair struct {
	Primary  string
	Previous string
}

// Sign computes the `X-Hash-Signature: t=<unix>,v1=<hex>` header value.
// The signed string is `${t}.${rawJSONBody}`. Same wire format brightcrm
// and atomicsite both use.
func Sign(secret string, body []byte, t time.Time) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify is exposed so unit tests (and the receiver-side helper, eventually)
// can confirm a signed message round-trips. Accepts either secret in the
// pair so rotations don't drop deliveries.
func Verify(secrets SignaturePair, body []byte, header string) bool {
	t, sig, ok := parseSignatureHeader(header)
	if !ok {
		return false
	}
	for _, s := range []string{secrets.Primary, secrets.Previous} {
		if s == "" {
			continue
		}
		mac := hmac.New(sha256.New, []byte(s))
		mac.Write([]byte(t))
		mac.Write([]byte{'.'})
		mac.Write(body)
		expected := hex.EncodeToString(mac.Sum(nil))
		if hmac.Equal([]byte(expected), []byte(sig)) {
			return true
		}
	}
	return false
}

func parseSignatureHeader(h string) (t, sig string, ok bool) {
	parts := strings.Split(h, ",")
	if len(parts) != 2 {
		return "", "", false
	}
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) != 2 {
			return "", "", false
		}
		switch kv[0] {
		case "t":
			t = kv[1]
		case "v1":
			sig = kv[1]
		}
	}
	return t, sig, t != "" && sig != ""
}

// Backoff returns the delay before the next attempt, given how many have
// already happened. Schedule: 1m, 5m, 25m, 2h, 12h, 24h. After six failed
// attempts the caller should mark the delivery `failed`.
func Backoff(attemptsSoFar int) (time.Duration, bool) {
	schedule := []time.Duration{
		1 * time.Minute,
		5 * time.Minute,
		25 * time.Minute,
		2 * time.Hour,
		12 * time.Hour,
		24 * time.Hour,
	}
	if attemptsSoFar < 0 || attemptsSoFar >= len(schedule) {
		return 0, false
	}
	return schedule[attemptsSoFar], true
}

// Dispatcher posts WebhookEvents over HTTP with HMAC signing and the
// retry envelope expected by the worker. The Secret field is the
// FALLBACK signing key used when DispatchWithSecret receives an empty
// per-endpoint secret (typical for legacy rows created before the
// 00024 migration). Construct via NewDispatcher.
type Dispatcher struct {
	HTTP   *http.Client
	Secret SignaturePair
	// AllowPrivate relaxes the SSRF guard for local dev/e2e (set from
	// config.IsLocalDevelopment). Production leaves it false.
	AllowPrivate bool
}

func NewDispatcher(secret SignaturePair) *Dispatcher {
	d := &Dispatcher{Secret: secret}
	d.HTTP = &http.Client{
		Timeout: 10 * time.Second,
		// Dial-time SSRF guard on the RESOLVED IP closes DNS rebinding: the
		// LookupIP checks in ValidateWebhookURL are a separate resolution a
		// short-TTL rebinding resolver can race, but the transport validates the
		// exact connect address. AllowPrivate is read live (set post-construct).
		Transport: nethard.Transport(func() bool { return d.AllowPrivate }),
		// Re-validate every redirect hop so a 3xx can't bounce the request
		// from an allowed host to an internal address, and cap the chain.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return ValidateWebhookURL(req.URL.String(), d.AllowPrivate)
		},
	}
	return d
}

// DispatchResult is what the worker persists to webhook_deliveries.
type DispatchResult struct {
	Status     int    // HTTP status returned (0 if connection failed)
	Body       string // up to 1KB of response body for diagnostics
	DurationMs int64
	Err        error
}

// Dispatch ships ev to url using the fallback instance-wide signing key.
// Prefer DispatchWithSecret for new code so each endpoint has its own
// per-row secret. Dispatch is retained for tests + the legacy code path
// that doesn't have an endpoint id at hand.
func (d *Dispatcher) Dispatch(ctx context.Context, url string, ev WebhookEvent) DispatchResult {
	return d.DispatchWithSecret(ctx, url, "", ev)
}

// DispatchWithSecret signs the payload with the supplied per-endpoint
// secret. Falls back to d.Secret.Primary (the instance-wide secret) when
// endpointSecret is empty so legacy rows created before the 00024
// migration still deliver. Returns an error when both are empty.
func (d *Dispatcher) DispatchWithSecret(ctx context.Context, url, endpointSecret string, ev WebhookEvent) DispatchResult {
	signingKey := endpointSecret
	if signingKey == "" {
		signingKey = d.Secret.Primary
	}
	if signingKey == "" {
		return DispatchResult{Err: errors.New("webhook secret not configured")}
	}
	// SSRF guard at delivery time (defense against DNS rebinding since the URL
	// was also validated at create time).
	if err := ValidateWebhookURL(url, d.AllowPrivate); err != nil {
		return DispatchResult{Err: err}
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return DispatchResult{Err: fmt.Errorf("marshal event: %w", err)}
	}
	sig := Sign(signingKey, body, time.Now().UTC())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return DispatchResult{Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hash-Signature", sig)
	req.Header.Set("X-Hash-Event", ev.Kind)
	req.Header.Set("User-Agent", "Hash-Webhook/1.0")

	start := time.Now()
	resp, err := d.HTTP.Do(req)
	dur := time.Since(start).Milliseconds()
	if err != nil {
		return DispatchResult{Err: err, DurationMs: dur}
	}
	defer resp.Body.Close()

	bodyBuf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return DispatchResult{
		Status:     resp.StatusCode,
		Body:       string(bodyBuf),
		DurationMs: dur,
	}
}
