// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"context"
	"encoding/json"

	"github.com/brightinteraction/hash/internal/db/generated"
)

// QueueingMailer implements Mailer by persisting each message to the
// email_deliveries table instead of sending it inline. The worker's
// email-dispatch loop drains the queue with backoff retries, so a transient
// SMTP outage never drops an invite, reminder, or completion email. Inject
// this everywhere an engine needs a Mailer; only the drain loop talks to SMTP.
type QueueingMailer struct {
	Q *generated.Queries
}

// Send enqueues the message. It returns an error only if the row cannot be
// written; actual delivery happens asynchronously in the worker.
func (m QueueingMailer) Send(ctx context.Context, msg Message) error {
	headers := json.RawMessage("{}")
	if len(msg.Headers) > 0 {
		if b, err := json.Marshal(msg.Headers); err == nil {
			headers = b
		}
	}
	_, err := m.Q.EnqueueEmailDelivery(ctx, generated.EnqueueEmailDeliveryParams{
		ToEmail:     msg.To,
		Subject:     msg.Subject,
		HtmlBody:    msg.HTML,
		TextBody:    msg.Text,
		ReplyTo:     msg.ReplyTo,
		FromName:    msg.FromName,
		HeadersJson: headers,
	})
	return err
}
