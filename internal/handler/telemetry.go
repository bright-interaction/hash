// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Legacy signer-telemetry wire validation remains here so historical data can
// still be classified and purged. New ingestion is disabled below until Hash
// has an auditable, server-enforced consent and withdrawal contract.

// telemetryBatch is the wire shape the signer script POSTs. Keeps the
// surface minimal: kind, optional block_id, free-form payload (capped).
type telemetryBatch struct {
	Events []telemetryEvent `json:"events"`
}

type telemetryEvent struct {
	Kind    string          `json:"kind"`
	BlockID string          `json:"block_id,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Per-token simple rate limiter: at most 30 batches/minute. Backed by an
// in-process token bucket; survives across requests but resets on restart
// (acceptable, telemetry is best-effort).
type telemetryRate struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens   float64
	maxBurst float64
	rate     float64 // tokens per second
	lastFill time.Time
}

func newTelemetryRate() *telemetryRate {
	return &telemetryRate{buckets: map[string]*tokenBucket{}}
}

func (l *telemetryRate) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		b = &tokenBucket{tokens: 30, maxBurst: 30, rate: 0.5, lastFill: time.Now()}
		l.buckets[key] = b
	}
	now := time.Now()
	b.tokens += now.Sub(b.lastFill).Seconds() * b.rate
	if b.tokens > b.maxBurst {
		b.tokens = b.maxBurst
	}
	b.lastFill = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

var telemetryLimiter = newTelemetryRate()

// validTelemetryKinds gates the kind enum the migration constrains, so we
// reject unknown event kinds at the HTTP boundary instead of as a DB error.
var validTelemetryKinds = map[string]bool{
	"session.start":     true,
	"session.end":       true,
	"block.viewed":      true,
	"page.scroll":       true,
	"interaction.click": true,
}

func validTelemetryEvent(ev telemetryEvent) bool {
	if !validTelemetryKinds[ev.Kind] {
		return false
	}
	// A view with no block cannot be attributed or rolled up. Persisting it
	// leaves rolled_up_at NULL forever and poisons the retention-edge
	// data-loss alarm, so reject it at the ingestion boundary.
	return ev.Kind != "block.viewed" || strings.TrimSpace(ev.BlockID) != ""
}

// maxBatchEvents caps a single batch at 200 events so a misbehaving client
// can't fill the table in one POST.
const maxBatchEvents = 200

// maxPayloadBytes caps each event's payload at 4 KiB so neither a malicious
// nor a bug-prone client can balloon row sizes.
const maxPayloadBytes = 4 * 1024

// POST /sign/{token}/telemetry
//
// Body: { "events": [{ "kind": "...", "block_id": "...", "payload": {...} }, ...] }
//
// Returns 204 on success (always; failures during insert are swallowed for
// individual rows so one bad event doesn't block the rest).
func (s *Server) handleSignerTelemetry(w http.ResponseWriter, r *http.Request) {
	// The earlier client-only opt-in was neither auditable nor enforceable: a
	// magic-link holder could POST directly without consent. Signer analytics
	// therefore fail closed in this release. Re-enable only with a persisted,
	// notice-versioned opt-in and withdrawal path enforced by this handler.
	writeError(w, http.StatusGone, "signer analytics are disabled")
}

// classifyUA maps a raw UA string to one of 'desktop', 'mobile', 'tablet',
// 'unknown'. Deliberately coarse so we capture device shape without
// fingerprinting; no version, no browser name.
func classifyUA(ua string) string {
	if ua == "" {
		return "unknown"
	}
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "ipad") || strings.Contains(lower, "tablet"):
		return "tablet"
	case strings.Contains(lower, "iphone") || strings.Contains(lower, "android") || strings.Contains(lower, "mobile"):
		return "mobile"
	case strings.Contains(lower, "mozilla") || strings.Contains(lower, "chrome") || strings.Contains(lower, "safari") || strings.Contains(lower, "firefox"):
		return "desktop"
	default:
		return "unknown"
	}
}

// errInvalidKind exposes the validation error so tests can assert on it.
var errInvalidKind = errors.New("invalid telemetry kind")
