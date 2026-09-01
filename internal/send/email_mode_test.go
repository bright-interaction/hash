// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
)

func TestAcknowledgementEmailModeReachesDurableOutbox(t *testing.T) {
	engine := &Engine{OrgName: "Partner Org"}
	for _, kind := range []string{dispatch.KindInvite, dispatch.KindReminder} {
		t.Run(kind, func(t *testing.T) {
			message, err := engine.renderEmail(
				kind,
				"recipient@example.test",
				"Recipient",
				"Policy",
				"sender@example.test",
				"https://hash.example.test/sign/token",
				"",
				"sv",
				false,
			)
			if err != nil {
				t.Fatal(err)
			}
			queue := &modeEmailQueue{}
			if err := enqueueLifecycleEmails(context.Background(), queue, []dispatch.Message{message}); err != nil {
				t.Fatal(err)
			}
			if len(queue.rows) != 1 {
				t.Fatalf("outbox rows = %d, want 1", len(queue.rows))
			}
			assertAcknowledgementLifecycleCopy(t, queue.rows[0].Subject+"\n"+queue.rows[0].HtmlBody+"\n"+queue.rows[0].TextBody)
		})
	}
}

func TestAcknowledgementEmailModeReachesLocalMailer(t *testing.T) {
	mailer := modeChannelMailer(make(chan dispatch.Message, 2))
	engine := &Engine{OrgName: "Partner Org", Mailer: mailer}
	for _, kind := range []string{dispatch.KindInvite, dispatch.KindReminder} {
		engine.sendEmail(
			kind,
			"recipient@example.test",
			"Recipient",
			"Policy",
			"sender@example.test",
			"https://hash.example.test/sign/token",
			"",
			"en",
			false,
		)
		select {
		case message := <-mailer:
			assertAcknowledgementLifecycleCopy(t, message.Subject+"\n"+message.HTML+"\n"+message.Text)
		case <-time.After(2 * time.Second):
			t.Fatalf("%s was not delivered to the local mailer", kind)
		}
	}
}

func assertAcknowledgementLifecycleCopy(t *testing.T, rendered string) {
	t.Helper()
	lower := strings.ToLower(rendered)
	if !strings.Contains(lower, "acknowledg") || !strings.Contains(lower, "no signature will be requested") {
		t.Fatalf("acknowledgement email lost its ceremony mode: %s", rendered)
	}
	for _, forbidden := range []string{"for signature", "review and sign", "awaiting your signature", "open and sign"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("acknowledgement email contains signing instruction %q: %s", forbidden, rendered)
		}
	}
}

type modeChannelMailer chan dispatch.Message

func (m modeChannelMailer) Send(ctx context.Context, message dispatch.Message) error {
	select {
	case m <- message:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type modeEmailQueue struct {
	rows []generated.EnqueueEmailDeliveryParams
}

func (q *modeEmailQueue) EnqueueEmailDelivery(_ context.Context, arg generated.EnqueueEmailDeliveryParams) (*generated.EmailDelivery, error) {
	q.rows = append(q.rows, arg)
	return &generated.EmailDelivery{ID: uuid.New(), ToEmail: arg.ToEmail}, nil
}
