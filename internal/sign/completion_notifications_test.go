// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
)

func TestPrepareCompletionNotificationsTxQueuesRecipientCredentialsAndSenderURL(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	doc := &generated.Document{
		ID: uuid.New(), SenderID: uuid.New(), Name: "Partner Agreement",
		Status: "completed", RequiresSignature: true,
	}
	signer := &generated.Recipient{ID: uuid.New(), DocumentID: doc.ID, Role: "signer", Status: "signed", Email: "signer@example.test", Name: "Signer", Locale: "en"}
	approver := &generated.Recipient{ID: uuid.New(), DocumentID: doc.ID, Role: "approver", Status: "signed", Email: "approver@example.test", Name: "Approver", Locale: "sv"}
	store := &completionStoreStub{
		recipients: []*generated.Recipient{
			signer,
			approver,
			{ID: uuid.New(), DocumentID: doc.ID, Role: "cc", Status: "signed", Email: "cc@example.test"},
			{ID: uuid.New(), DocumentID: doc.ID, Role: "signer", Status: "viewed", Email: "waiting@example.test"},
		},
		sender: &generated.User{ID: doc.SenderID, Email: "sender@example.test", Name: "Sender"},
	}
	engine := &Engine{
		Mailer: dispatch.QueueingMailer{}, BaseURL: "https://hash.example.test/", OrgName: "Hash Test",
		Now: func() time.Time { return now },
	}
	oldCeremonyToken := "old-ceremony-token"
	signer.MagicTokenHash = auth.HashMagicToken(oldCeremonyToken)
	capture := &completionCredentialCapture{recipientID: signer.ID}

	messages, err := engine.prepareCompletionNotificationsTx(context.Background(), store, doc, map[string]struct{}{"signer": {}, "approver": {}}, capture)
	if err != nil {
		t.Fatalf("prepare completion notifications: %v", err)
	}
	if len(messages) != 3 || len(store.enqueued) != 3 {
		t.Fatalf("messages/enqueued = %d/%d, want two external recipients plus sender", len(messages), len(store.enqueued))
	}
	if len(store.rotations) != 2 {
		t.Fatalf("token rotations = %d, want only required signed recipients", len(store.rotations))
	}

	rotationsByID := map[uuid.UUID]generated.RotateCompletedArtifactTokenParams{}
	for _, rotation := range store.rotations {
		rotationsByID[rotation.ID] = rotation
		if !rotation.MagicTokenExpiresAt.Valid || !rotation.MagicTokenExpiresAt.Time.Equal(now.Add(completedArtifactAccessTTL)) {
			t.Fatalf("rotation expiry = %v, want %v", rotation.MagicTokenExpiresAt, now.Add(completedArtifactAccessTTL))
		}
	}
	for _, recipient := range []*generated.Recipient{signer, approver} {
		message := messageTo(t, messages, recipient.Email)
		rawToken := completionTokenFromMessage(t, message)
		rotation, ok := rotationsByID[recipient.ID]
		if !ok {
			t.Fatalf("missing rotation for %s", recipient.Email)
		}
		if !bytes.Equal(auth.HashMagicToken(rawToken), rotation.MagicTokenHash) {
			t.Fatalf("email credential for %s does not match persisted token hash", recipient.Email)
		}
		assertContains(t, message.HTML+message.Text, "https://hash.example.test/sign/"+rawToken+"/final-pdf")
		assertNotContains(t, message.HTML+message.Text, "/api/v1/documents/")
	}
	if capture.rawToken == "" || capture.rawToken == oldCeremonyToken {
		t.Fatalf("completing recipient token = %q, want a fresh result credential", capture.rawToken)
	}
	if got := completedArtifactPath(capture.rawToken); got == completedArtifactPath(oldCeremonyToken) || got != "/sign/"+capture.rawToken+"/final-pdf" {
		t.Fatalf("returned final PDF path = %q, want fresh completion credential", got)
	}
	if bytes.Equal(auth.HashMagicToken(oldCeremonyToken), rotationsByID[signer.ID].MagicTokenHash) {
		t.Fatal("completion preserved the old ceremony credential instead of rotating it")
	}

	senderMessage := messageTo(t, messages, store.sender.Email)
	assertContains(t, senderMessage.HTML+senderMessage.Text, "https://hash.example.test/api/v1/documents/"+doc.ID.String()+"/final-pdf")
	assertNotContains(t, senderMessage.HTML+senderMessage.Text, "/sign/")
}

func TestPrepareCompletionNotificationsTxAcknowledgementIncludesAcceptedNonCC(t *testing.T) {
	doc := &generated.Document{
		ID: uuid.New(), SenderID: uuid.New(), Name: "Policy Acknowledgement",
		Status: "completed", RequiresSignature: false,
	}
	accepted := &generated.Recipient{ID: uuid.New(), DocumentID: doc.ID, Role: "approver", Status: "accepted", Email: "accepted@example.test", Name: "Accepted"}
	store := &completionStoreStub{
		recipients: []*generated.Recipient{
			accepted,
			{ID: uuid.New(), DocumentID: doc.ID, Role: "cc", Status: "accepted", Email: "cc@example.test"},
			{ID: uuid.New(), DocumentID: doc.ID, Role: "approver", Status: "declined", Email: "declined@example.test"},
			{ID: uuid.New(), DocumentID: doc.ID, Role: "approver", Status: "signed", Email: "signed@example.test"},
		},
		sender: &generated.User{ID: doc.SenderID, Email: "sender@example.test", Name: "Sender"},
	}
	engine := &Engine{Mailer: dispatch.QueueingMailer{}, BaseURL: "https://hash.example.test", OrgName: "Hash Test"}

	messages, err := engine.prepareCompletionNotificationsTx(context.Background(), store, doc, nil, nil)
	if err != nil {
		t.Fatalf("prepare acknowledgement notifications: %v", err)
	}
	if len(store.rotations) != 1 || store.rotations[0].ID != accepted.ID {
		t.Fatalf("rotations = %#v, want accepted non-cc recipient only", store.rotations)
	}
	if len(messages) != 2 || len(store.enqueued) != 2 {
		t.Fatalf("messages/enqueued = %d/%d, want accepted recipient plus sender", len(messages), len(store.enqueued))
	}
	acceptedMessage := messageTo(t, messages, accepted.Email)
	_ = completionTokenFromMessage(t, acceptedMessage)
	acceptedCopy := strings.ToLower(acceptedMessage.Subject + "\n" + acceptedMessage.HTML + "\n" + acceptedMessage.Text)
	assertContains(t, acceptedCopy, "acknowledgements are complete")
	assertContains(t, acceptedCopy, "no signature image or representation")
	assertNotContains(t, acceptedCopy, "your signed copy")

	senderMessage := messageTo(t, messages, store.sender.Email)
	senderCopy := strings.ToLower(senderMessage.Subject + "\n" + senderMessage.HTML + "\n" + senderMessage.Text)
	assertContains(t, senderCopy, "acknowledgements complete")
	assertContains(t, senderCopy, "no signature image or representation")
	assertNotContains(t, senderCopy, "signing ceremony")
}

func TestPrepareCompletionNotificationsTxQueueFailureIsReturned(t *testing.T) {
	wantErr := errors.New("email outbox unavailable")
	doc := &generated.Document{ID: uuid.New(), SenderID: uuid.New(), Name: "Agreement", Status: "completed", RequiresSignature: true}
	store := &completionStoreStub{
		recipients: []*generated.Recipient{{ID: uuid.New(), DocumentID: doc.ID, Role: "signer", Status: "signed", Email: "signer@example.test", Name: "Signer"}},
		sender:     &generated.User{ID: doc.SenderID, Email: "sender@example.test", Name: "Sender"},
		enqueueErr: wantErr,
		enqueueAt:  2,
	}
	engine := &Engine{Mailer: dispatch.QueueingMailer{}, BaseURL: "https://hash.example.test", OrgName: "Hash Test"}

	_, err := engine.prepareCompletionNotificationsTx(context.Background(), store, doc, map[string]struct{}{"signer": {}}, nil)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want wrapped outbox failure", err)
	}
	if len(store.enqueued) != 2 {
		t.Fatalf("enqueue attempts = %d, want stop at failing sender enqueue", len(store.enqueued))
	}
}

func TestDeliverPostCommitEmailsIsSynchronousOnlyForNonQueueMailer(t *testing.T) {
	recorder := &dispatch.RecordingMailer{}
	engine := &Engine{Mailer: recorder}
	messages := []dispatch.Message{{To: "first@example.test"}, {To: "second@example.test"}}

	engine.deliverPostCommitEmails(messages)
	if len(recorder.Sent) != len(messages) {
		t.Fatalf("synchronous sends = %d, want %d", len(recorder.Sent), len(messages))
	}

	engine.Mailer = dispatch.QueueingMailer{}
	engine.deliverPostCommitEmails(messages)
	if len(recorder.Sent) != len(messages) {
		t.Fatal("queue-backed completion must not send after commit")
	}
}

type completionStoreStub struct {
	recipients []*generated.Recipient
	sender     *generated.User
	rotations  []generated.RotateCompletedArtifactTokenParams
	enqueued   []generated.EnqueueEmailDeliveryParams
	rotateRows int64
	rotateErr  error
	enqueueAt  int
	enqueueErr error
}

func (s *completionStoreStub) ListRecipientsByDocument(_ context.Context, _ uuid.UUID) ([]*generated.Recipient, error) {
	return s.recipients, nil
}

func (s *completionStoreStub) RotateCompletedArtifactToken(_ context.Context, arg generated.RotateCompletedArtifactTokenParams) (int64, error) {
	s.rotations = append(s.rotations, arg)
	if s.rotateErr != nil {
		return 0, s.rotateErr
	}
	if s.rotateRows != 0 {
		return s.rotateRows, nil
	}
	return 1, nil
}

func (s *completionStoreStub) GetUser(_ context.Context, _ uuid.UUID) (*generated.User, error) {
	if s.sender == nil {
		return nil, errors.New("sender unavailable")
	}
	return s.sender, nil
}

func (s *completionStoreStub) EnqueueEmailDelivery(_ context.Context, arg generated.EnqueueEmailDeliveryParams) (*generated.EmailDelivery, error) {
	s.enqueued = append(s.enqueued, arg)
	if s.enqueueErr != nil && len(s.enqueued) == s.enqueueAt {
		return nil, s.enqueueErr
	}
	return &generated.EmailDelivery{ID: uuid.New(), ToEmail: arg.ToEmail}, nil
}

func messageTo(t *testing.T, messages []dispatch.Message, to string) dispatch.Message {
	t.Helper()
	for _, message := range messages {
		if message.To == to {
			return message
		}
	}
	t.Fatalf("no completion message to %s", to)
	return dispatch.Message{}
}

func completionTokenFromMessage(t *testing.T, message dispatch.Message) string {
	t.Helper()
	content := message.HTML + "\n" + message.Text
	marker := "/sign/"
	start := strings.Index(content, marker)
	if start < 0 {
		t.Fatalf("message has no signer download credential: %s", content)
	}
	start += len(marker)
	relativeEnd := strings.Index(content[start:], "/final-pdf")
	if relativeEnd <= 0 {
		t.Fatalf("message has malformed signer download credential: %s", content)
	}
	return content[start : start+relativeEnd]
}

func assertContains(t *testing.T, value, fragment string) {
	t.Helper()
	if !strings.Contains(value, fragment) {
		t.Fatalf("value does not contain %q: %s", fragment, value)
	}
}

func assertNotContains(t *testing.T, value, fragment string) {
	t.Helper()
	if strings.Contains(value, fragment) {
		t.Fatalf("value unexpectedly contains %q: %s", fragment, value)
	}
}
