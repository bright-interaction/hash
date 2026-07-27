// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// RegisterWebhookFanout wires the audit.Logger post-insert hook that enqueues a
// webhook delivery for every public event kind. It MUST be called from both the
// server and the worker binaries: the worker emits document.expired and
// reminder.sent, and previously only the server registered the fan-out, so
// those worker-driven events never reached customer webhooks.
func RegisterWebhookFanout(auditLog *audit.Logger, queries *generated.Queries) {
	auditLog.Subscribe(func(ctx context.Context, eventID uuid.UUID, e audit.Entry) {
		if !IsPublicEventKind(e.Kind) {
			return
		}
		payload := map[string]any{}
		for k, v := range e.Payload {
			payload[k] = v
		}
		if e.DocumentID != nil {
			payload["document_id"] = e.DocumentID.String()
		}
		if e.RecipientID != nil {
			payload["recipient_id"] = e.RecipientID.String()
		}
		if err := Enqueue(ctx, queries, e.OrgID, eventID, WebhookEvent{
			EventID:    eventID.String(),
			Kind:       e.Kind,
			OccurredAt: time.Now().UTC(),
			OrgID:      e.OrgID.String(),
			Payload:    payload,
		}); err != nil {
			slog.Warn("webhook fan-out failed", "kind", e.Kind, "err", err)
		}
	})
}
