// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/resolver"
)

// Phase 9.1: BrightCRM webhook receiver.
//
// BrightCRM emits `deal.updated`, `contact.updated`, and a handful of
// other events when CRM data changes. Hash subscribes so the variable
// resolver cache can be invalidated for affected source refs; the next
// editor reload picks up the live value within the resolver's normal
// fetch path instead of serving a 30-second-stale cache hit.
//
// Wire format mirrors the existing brightcrm outbound webhook signing:
//   X-BrightCRM-Signature: t=<unix>,v1=<hex>
//   Body: { "event": "deal.updated", "data": { "id": "...", ... } }
//
// HMAC-SHA256 over "t=<ts>." + body, comparing against the shared
// secret. Returns 204 on success even when the resolver isn't
// configured, so the sender retries don't accumulate.

const brightCRMSignatureHeader = "X-BrightCRM-Signature"
const brightCRMMaxSkew = 5 * time.Minute

type brightCRMEvent struct {
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
}

type brightCRMEntity struct {
	ID string `json:"id"`
}

// POST /webhooks/brightcrm
//
// Verifies HMAC signature, parses event, maps event -> source_kind, and
// calls Resolver.InvalidateForSource. Authentication is the signature
// itself; no session, no API key.
func (s *Server) handleBrightCRMWebhook(w http.ResponseWriter, r *http.Request) {
	if s.Resolver == nil {
		// Resolver not wired (test stack). Acknowledge without invalidating.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1*1024*1024)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	secret := s.BrightCRMWebhookSecret
	if secret == "" {
		// Defense in depth: config validation (internal/config) already
		// refuses to boot in production without a secret, but a misconfigured
		// runtime override or a stripped-down test stack could still land
		// here. Fail-closed outside local dev so a missing secret never
		// silently waves through arbitrary cache invalidations.
		if !config.IsLocalDevelopment(s.PublicURL) {
			writeError(w, http.StatusServiceUnavailable, "brightcrm webhook secret not configured")
			return
		}
	} else {
		if err := verifyBrightCRMSignature(r.Header.Get(brightCRMSignatureHeader), secret, body, time.Now()); err != nil {
			writeError(w, http.StatusUnauthorized, "signature: "+err.Error())
			return
		}
	}
	var ev brightCRMEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		writeError(w, http.StatusBadRequest, "decode: "+err.Error())
		return
	}
	kind := mapBrightCRMEventToSourceKind(ev.Event)
	if kind == "" {
		// Event we don't care about; acknowledge and move on.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var entity brightCRMEntity
	if err := json.Unmarshal(ev.Data, &entity); err != nil || entity.ID == "" {
		writeError(w, http.StatusBadRequest, "data.id required")
		return
	}
	dropped := s.Resolver.InvalidateForSource(kind, entity.ID)
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: noOrgUUID(),
		Kind:  audit.KindWebhookDispatched, // reuse closest enum; brightcrm-inbound taxonomy lands later
		Payload: map[string]any{
			"via":         "inbound",
			"source":      "brightcrm",
			"event":       ev.Event,
			"source_kind": kind,
			"source_ref":  entity.ID,
			"dropped":     dropped,
		},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged":      true,
		"event":             ev.Event,
		"invalidated_count": dropped,
	})
}

// mapBrightCRMEventToSourceKind returns the resolver source_kind for a
// BrightCRM event name, or "" if the event isn't actionable.
func mapBrightCRMEventToSourceKind(event string) string {
	switch event {
	case "deal.updated", "deal.deleted", "deal.created":
		return string(resolver.SourceCRMDeal)
	case "contact.updated", "contact.deleted", "contact.created":
		return string(resolver.SourceCRMContact)
	default:
		return ""
	}
}

// verifyBrightCRMSignature checks the t=<unix>,v1=<hex> header against
// secret + body. Returns nil on a valid signature within brightCRMMaxSkew.
func verifyBrightCRMSignature(header, secret string, body []byte, now time.Time) error {
	if header == "" {
		return fmt.Errorf("missing %s header", brightCRMSignatureHeader)
	}
	var ts, sigHex string
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			ts = kv[1]
		case "v1":
			sigHex = kv[1]
		}
	}
	if ts == "" || sigHex == "" {
		return fmt.Errorf("malformed signature header")
	}
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return fmt.Errorf("bad timestamp")
	}
	tsTime := time.Unix(tsInt, 0)
	if diff := now.Sub(tsTime); diff > brightCRMMaxSkew || diff < -brightCRMMaxSkew {
		return fmt.Errorf("timestamp skew too large")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("t=" + ts + "."))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	got, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("signature not hex")
	}
	wantBytes, _ := hex.DecodeString(want)
	if !hmac.Equal(wantBytes, got) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

// noOrgUUID is the zero org id we use for system-attributed events
// (inbound webhook hits arrive before we know which org they apply to;
// the resolver invalidation is process-wide).
func noOrgUUID() (zero [16]byte) {
	return [16]byte{}
}
