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

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/db/generated"
)

// Phase 8.3 telemetry endpoint. Signer-side script POSTs batched events
// every 5s and on beforeunload via navigator.sendBeacon. The endpoint is
// magic-token-authed (same magic link as the rest of /sign/{token}/*) and
// rate-limited per token to keep noisy clients from filling the table.

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
	tok := chi.URLParam(r, "token")
	if tok == "" {
		writeError(w, http.StatusBadRequest, "missing token")
		return
	}
	if !telemetryLimiter.allow(tok) {
		writeError(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	// Limit request body to 256 KiB so even a 200-event batch with
	// max-payload events fits while a runaway client gets 413'd.
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
	var batch telemetryBatch
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if len(batch.Events) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if len(batch.Events) > maxBatchEvents {
		writeError(w, http.StatusBadRequest, "batch too large")
		return
	}
	ipGeo := strings.ToUpper(strings.TrimSpace(r.Header.Get("CF-IPCountry")))
	if len(ipGeo) != 2 {
		ipGeo = "" // never store full IPs; country-only or nothing
	}
	uaClass := classifyUA(r.UserAgent())
	docID := rc.Document.ID
	recID := rc.Recipient.ID

	inserted := 0
	for _, ev := range batch.Events {
		if !validTelemetryKinds[ev.Kind] {
			continue
		}
		if len(ev.Payload) > maxPayloadBytes {
			continue
		}
		if len(ev.Payload) == 0 {
			ev.Payload = json.RawMessage("{}")
		}
		var blockID pgtype.Text
		if ev.BlockID != "" {
			blockID = pgtype.Text{String: ev.BlockID, Valid: true}
		}
		_, err := s.Queries.InsertTelemetryEvent(r.Context(), generated.InsertTelemetryEventParams{
			DocumentID:  docID,
			RecipientID: recID,
			Kind:        ev.Kind,
			BlockID:     blockID,
			PayloadJson: ev.Payload,
			IpGeo:       ipGeo,
			UaClass:     uaClass,
		})
		if err != nil {
			// One bad event doesn't kill the batch.
			continue
		}
		inserted++
	}
	w.WriteHeader(http.StatusNoContent)
	_ = inserted // available for future audit/metrics; intentionally not returned to client
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
