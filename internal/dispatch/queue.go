package dispatch

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/brightinteraction/hash/internal/db/generated"
)

// PublicEventKinds is the set of audit kinds that fan out to outbound
// webhooks. Internal-only kinds (clarifier, billing, risk analysis,
// collab presence) are NOT in this list ,  customers don't subscribe to
// AI-runtime chatter.
//
// Update this set when adding a new public event surface. The hook in
// cmd/server checks membership before enqueuing.
var PublicEventKinds = map[string]struct{}{
	"document.created":      {},
	"document.sent":         {},
	"document.opened":       {},
	"document.viewed":       {},
	"document.field_filled": {},
	"document.signed":       {},
	"document.completed":    {},
	"document.declined":     {},
	"document.voided":       {},
	"document.expired":      {},
	"recipient.invited":     {},
	"recipient.bounced":     {},
}

// IsPublicEventKind reports whether kind is in PublicEventKinds. Callers
// that want to gate webhook fan-out (the audit hook in cmd/server) use
// this to avoid leaking internal events to customer subscribers.
func IsPublicEventKind(kind string) bool {
	_, ok := PublicEventKinds[kind]
	return ok
}

// Enqueue creates webhook_deliveries rows for every active endpoint in the
// org subscribed to ev.Kind. The worker picks them up on its next tick.
//
// Caller must already have inserted the events row (and uses its id as
// ev.EventID).
func Enqueue(ctx context.Context, q *generated.Queries, orgID uuid.UUID, eventID uuid.UUID, ev WebhookEvent) error {
	endpoints, err := q.ListActiveWebhookEndpointsForEvent(ctx, generated.ListActiveWebhookEndpointsForEventParams{
		OrgID: orgID,
		Kind:  ev.Kind,
	})
	if err != nil {
		return fmt.Errorf("list endpoints: %w", err)
	}
	for _, ep := range endpoints {
		if _, err := q.EnqueueWebhookDelivery(ctx, generated.EnqueueWebhookDeliveryParams{
			EndpointID: ep.ID,
			EventID:    eventID,
		}); err != nil {
			return fmt.Errorf("enqueue delivery for %s: %w", ep.Url, err)
		}
	}
	return nil
}

// LoadEvent fetches the events row for a delivery so the worker can
// reconstruct the WebhookEvent payload it needs to sign + ship.
func LoadEvent(ctx context.Context, q *generated.Queries, eventID uuid.UUID) (WebhookEvent, error) {
	e, err := q.GetEventByID(ctx, eventID)
	if err != nil {
		return WebhookEvent{}, fmt.Errorf("get event: %w", err)
	}
	payload := map[string]any{}
	if len(e.PayloadJson) > 0 {
		_ = json.Unmarshal(e.PayloadJson, &payload)
	}
	return WebhookEvent{
		EventID:    e.ID.String(),
		Kind:       e.Kind,
		OccurredAt: e.CreatedAt.Time,
		OrgID:      e.OrgID.String(),
		Payload:    payload,
	}, nil
}

// PendingDelivery is the joined view the worker iterates on.
type PendingDelivery struct {
	DeliveryID uuid.UUID
	EndpointID uuid.UUID
	EventID    uuid.UUID
	URL        string
	Attempts   int32
}

// nextAttempt computes the absolute timestamp for the next retry. Caller
// passes the prior attempts count; returns (when, true) if we should retry,
// (zero, false) if we're past the schedule and should mark `failed`.
func nextAttempt(attemptsSoFar int) (time.Time, bool) {
	d, ok := Backoff(attemptsSoFar)
	if !ok {
		return time.Time{}, false
	}
	return time.Now().Add(d), true
}
