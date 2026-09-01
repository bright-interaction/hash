// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
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
// Wire format accepts the current BrightCRM dispatcher contract:
//   X-BrightCRM-Signature: sha256=<hex HMAC of body>
//   X-BrightCRM-Delivery-ID: <stable retry id> (present on durable dispatches)
//   Body: { "id": "<same retry id>", "event": "deal.updated", "data": { "id": "...", ... } }
//
// The timestamped t=<unix>,v1=<hex HMAC of "t=<ts>." + body> format is
// retained for a bounded compatibility window. Both formats require a stable
// delivery id in the signed body so retries can be deduplicated transactionally;
// when the redundant header is present it must match exactly.

const brightCRMSignatureHeader = "X-BrightCRM-Signature"
const brightCRMDeliveryIDHeader = "X-BrightCRM-Delivery-ID"
const brightCRMMaxSkew = 5 * time.Minute

type brightCRMEvent struct {
	ID    string          `json:"id"`
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
}

type brightCRMEntity struct {
	ID string `json:"id"`
}

type brightCRMWebhookProcessInput struct {
	SourceKind                 string
	SourceRef                  string
	DeliveryCorrelation        string
	DeliveryPayloadCorrelation string
	AuditPayload               map[string]any
}

type brightCRMWebhookProcessResult struct {
	OrgIDs    []uuid.UUID
	Duplicate bool
}

type brightCRMWebhookProcessor interface {
	processBrightCRMWebhook(context.Context, brightCRMWebhookProcessInput) (brightCRMWebhookProcessResult, error)
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
		// A localhost URL is not an authentication boundary: development and
		// isolated stacks are often published through a proxy or shared LAN.
		// Resolver=nil above is the explicit disabled/no-op mode; every active
		// receiver fails closed when its secret is absent.
		writeError(w, http.StatusServiceUnavailable, "brightcrm webhook secret not configured")
		return
	}
	if err := verifyBrightCRMSignature(r.Header.Get(brightCRMSignatureHeader), secret, body, time.Now()); err != nil {
		writeError(w, http.StatusUnauthorized, "signature: "+err.Error())
		return
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
	deliveryID := ev.ID
	deliveryHeader := strings.TrimSpace(r.Header.Get(brightCRMDeliveryIDHeader))
	if !validBrightCRMDeliveryID(deliveryID) || (deliveryHeader != "" && deliveryHeader != deliveryID) {
		writeError(w, http.StatusBadRequest, "stable delivery id required")
		return
	}
	var entity brightCRMEntity
	if err := json.Unmarshal(ev.Data, &entity); err != nil || entity.ID == "" {
		writeError(w, http.StatusBadRequest, "data.id required")
		return
	}
	processor := s.brightCRMProcessor()
	if processor == nil {
		writeError(w, http.StatusServiceUnavailable, "brightcrm webhook audit unavailable")
		return
	}

	// A source reference and a small webhook body may be customer/contact data
	// with a guessable value. Store only domain-separated, keyed correlation
	// tokens in the long-lived audit ledger. They correlate retries while the
	// configured webhook secret is active and intentionally change on rotation.
	refCorrelation := brightCRMAuditCorrelation(secret, "source-ref", []byte(kind+"\x00"+entity.ID))
	bodyCorrelation := brightCRMAuditCorrelation(secret, "body", body)
	deliveryCorrelation := brightCRMAuditCorrelation(secret, "delivery-id", []byte(deliveryID))
	deliveryPayloadCorrelation, err := brightCRMDeliveryPayloadCorrelation(secret, ev)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid delivery payload")
		return
	}
	result, err := processor.processBrightCRMWebhook(r.Context(), brightCRMWebhookProcessInput{
		SourceKind:                 kind,
		SourceRef:                  entity.ID,
		DeliveryCorrelation:        deliveryCorrelation,
		DeliveryPayloadCorrelation: deliveryPayloadCorrelation,
		AuditPayload: map[string]any{
			"via":                    "inbound",
			"source":                 "brightcrm",
			"event":                  canonicalBrightCRMEvent(ev.Event),
			"source_kind":            kind,
			"correlation_schema":     "hash-brightcrm-hmac-sha256-v1",
			"source_ref_correlation": refCorrelation,
			"body_correlation":       bodyCorrelation,
			"delivery_correlation":   deliveryCorrelation,
		},
	})
	if errors.Is(err, errBrightCRMDeliveryConflict) {
		writeError(w, http.StatusUnprocessableEntity, "brightcrm delivery id reused with different content")
		return
	}
	if err != nil {
		slog.Error("brightcrm webhook atomic audit failed", "event", canonicalBrightCRMEvent(ev.Event), "source_kind", kind, "err", err)
		writeError(w, http.StatusServiceUnavailable, "brightcrm webhook processing temporarily unavailable")
		return
	}

	// No matching tenant means there is no authorized cache mutation to make.
	// Once every affected tenant ledger has durably recorded the event, the
	// process-local invalidation can safely happen.
	dropped := 0
	if len(result.OrgIDs) > 0 {
		dropped = s.Resolver.InvalidateForSourceOrgs(kind, entity.ID, result.OrgIDs)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"acknowledged":      true,
		"duplicate":         result.Duplicate,
		"event":             canonicalBrightCRMEvent(ev.Event),
		"invalidated_count": dropped,
	})
}

func brightCRMAuditCorrelation(secret, domain string, value []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("hash:brightcrm:audit:v1\x00" + domain + "\x00"))
	_, _ = mac.Write(value)
	return hex.EncodeToString(mac.Sum(nil))
}

// brightCRMDeliveryPayloadCorrelation excludes the dispatcher's informational
// timestamp: BrightCRM rebuilds that timestamp when retrying the same stable
// delivery id. The event and data remain signed and are the semantic payload
// whose reuse under one delivery id would be a collision.
func brightCRMDeliveryPayloadCorrelation(secret string, event brightCRMEvent) (string, error) {
	if !json.Valid(event.Data) {
		return "", errors.New("invalid BrightCRM data JSON")
	}
	canonical, err := json.Marshal(struct {
		Event string          `json:"event"`
		Data  json.RawMessage `json:"data"`
	}{Event: canonicalBrightCRMEvent(event.Event), Data: event.Data})
	if err != nil {
		return "", err
	}
	return brightCRMAuditCorrelation(secret, "delivery-payload", canonical), nil
}

func (s *Server) brightCRMProcessor() brightCRMWebhookProcessor {
	if s.brightCRMProcessorOverride != nil {
		return s.brightCRMProcessorOverride
	}
	if s.Pool == nil || s.Queries == nil || s.Audit == nil {
		return nil
	}
	return s
}

// processBrightCRMWebhook claims the provider receipt and appends every
// affected organization ledger in one transaction. Organization ids come from
// a sorted query, giving overlapping multi-tenant deliveries a stable advisory
// lock order. Hooks are released only after the complete transaction commits.
func (s *Server) processBrightCRMWebhook(ctx context.Context, input brightCRMWebhookProcessInput) (brightCRMWebhookProcessResult, error) {
	if s.Pool == nil || s.Queries == nil || s.Audit == nil {
		return brightCRMWebhookProcessResult{}, errors.New("durable BrightCRM dependencies unavailable")
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return brightCRMWebhookProcessResult{}, fmt.Errorf("begin BrightCRM webhook transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Queries.WithTx(tx)
	if _, err := q.PurgeExpiredBrightCRMWebhookReceipts(ctx); err != nil {
		return brightCRMWebhookProcessResult{}, fmt.Errorf("purge BrightCRM webhook receipts: %w", err)
	}
	orgIDs, err := q.ListOrgIDsForVariableSource(ctx, generated.ListOrgIDsForVariableSourceParams{
		SourceKind: input.SourceKind,
		SourceRef:  input.SourceRef,
	})
	if err != nil {
		return brightCRMWebhookProcessResult{}, fmt.Errorf("resolve BrightCRM webhook tenants: %w", err)
	}
	if err := validateSortedBrightCRMOrgIDs(orgIDs); err != nil {
		return brightCRMWebhookProcessResult{}, err
	}
	claimed, err := q.ClaimBrightCRMWebhookReceipt(ctx, generated.ClaimBrightCRMWebhookReceiptParams{
		DeliveryCorrelation: input.DeliveryCorrelation,
		PayloadCorrelation:  input.DeliveryPayloadCorrelation,
		OrgIds:              orgIDs,
	})
	if err != nil {
		return brightCRMWebhookProcessResult{}, fmt.Errorf("claim BrightCRM webhook receipt: %w", err)
	}
	if claimed != 0 && claimed != 1 {
		return brightCRMWebhookProcessResult{}, errors.New("BrightCRM webhook receipt claim affected an invalid row count")
	}
	duplicate := claimed == 0
	if duplicate {
		committed, err := q.GetBrightCRMWebhookReceipt(ctx, input.DeliveryCorrelation)
		if err != nil {
			return brightCRMWebhookProcessResult{}, fmt.Errorf("read BrightCRM webhook receipt: %w", err)
		}
		if len(committed.PayloadCorrelation) != len(input.DeliveryPayloadCorrelation) ||
			subtle.ConstantTimeCompare([]byte(committed.PayloadCorrelation), []byte(input.DeliveryPayloadCorrelation)) != 1 {
			return brightCRMWebhookProcessResult{}, errBrightCRMDeliveryConflict
		}
		orgIDs = committed.OrgIds
		if err := validateSortedBrightCRMOrgIDs(orgIDs); err != nil {
			return brightCRMWebhookProcessResult{}, fmt.Errorf("read BrightCRM webhook receipt tenant snapshot: %w", err)
		}
	}

	pending := make([]audit.PendingEvent, 0, len(orgIDs))
	if !duplicate {
		for _, orgID := range orgIDs {
			event, err := s.Audit.LogTx(ctx, tx, audit.Entry{
				OrgID: orgID, Kind: audit.KindWebhookReceived, Payload: input.AuditPayload,
			})
			if err != nil {
				return brightCRMWebhookProcessResult{}, fmt.Errorf("append BrightCRM audit for tenant: %w", err)
			}
			pending = append(pending, event)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return brightCRMWebhookProcessResult{}, fmt.Errorf("commit BrightCRM webhook transaction: %w", err)
	}
	for _, event := range pending {
		s.Audit.Publish(event)
	}
	return brightCRMWebhookProcessResult{OrgIDs: orgIDs, Duplicate: duplicate}, nil
}

var errBrightCRMDeliveryConflict = errors.New("BrightCRM delivery id was replayed with different content")

func validateSortedBrightCRMOrgIDs(orgIDs []uuid.UUID) error {
	for i, orgID := range orgIDs {
		if orgID == uuid.Nil || (i > 0 && orgIDs[i-1].String() >= orgID.String()) {
			return errors.New("BrightCRM tenant lookup returned invalid ordering")
		}
	}
	return nil
}

// mapBrightCRMEventToSourceKind returns the resolver source_kind for a
// BrightCRM event name, or "" if the event isn't actionable.
func mapBrightCRMEventToSourceKind(event string) string {
	switch canonicalBrightCRMEvent(event) {
	case "deal.updated", "deal.deleted", "deal.created":
		return string(resolver.SourceCRMDeal)
	case "contact.updated", "contact.deleted", "contact.created":
		return string(resolver.SourceCRMContact)
	default:
		return ""
	}
}

func canonicalBrightCRMEvent(event string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(event), "_", "."))
}

func validBrightCRMDeliveryID(deliveryID string) bool {
	if deliveryID == "" || len(deliveryID) > 200 {
		return false
	}
	for _, r := range deliveryID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ':' {
			continue
		}
		return false
	}
	return true
}

// verifyBrightCRMSignature accepts the current body-HMAC contract and the
// timestamped compatibility contract. Replay prevention is handled by the
// separately signed, stable delivery id after this cryptographic check.
func verifyBrightCRMSignature(header, secret string, body []byte, now time.Time) error {
	if header == "" {
		return fmt.Errorf("missing %s header", brightCRMSignatureHeader)
	}
	if strings.HasPrefix(header, "sha256=") && !strings.Contains(header, ",") {
		sigHex := strings.TrimPrefix(header, "sha256=")
		got, err := decodeCanonicalBrightCRMMAC(sigHex)
		if err != nil {
			return err
		}
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(body)
		if !hmac.Equal(mac.Sum(nil), got) {
			return errors.New("signature mismatch")
		}
		return nil
	}

	var ts, sigHex string
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			if ts != "" {
				return errors.New("duplicate timestamp")
			}
			ts = kv[1]
		case "v1":
			if sigHex != "" {
				return errors.New("duplicate signature")
			}
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
	got, err := decodeCanonicalBrightCRMMAC(sigHex)
	if err != nil {
		return err
	}
	wantBytes, _ := hex.DecodeString(want) // want is internal canonical hex.
	if !hmac.Equal(wantBytes, got) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func decodeCanonicalBrightCRMMAC(value string) ([]byte, error) {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return nil, errors.New("signature is not canonical SHA-256 hex")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, errors.New("signature is not canonical SHA-256 hex")
	}
	return decoded, nil
}
