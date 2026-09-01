// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/storage"
)

func TestAppendAuditEntriesTxPropagatesFailureForCallerRollback(t *testing.T) {
	wantErr := errors.New("audit insert failed")
	logger := &fakeAuditAppender{failAt: 2, err: wantErr}
	entries := []audit.Entry{
		{OrgID: uuid.New(), Kind: audit.KindRecipientInvited},
		{OrgID: uuid.New(), Kind: audit.KindDocumentSent},
		{OrgID: uuid.New(), Kind: audit.KindDocumentSent},
	}

	got, err := appendAuditEntriesTx(context.Background(), logger, nil, entries)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want wrapped audit failure", err)
	}
	if got != nil {
		t.Fatalf("pending events = %#v, want nil on rollback path", got)
	}
	if len(logger.calls) != 2 {
		t.Fatalf("audit calls = %d, want stop at failed insert", len(logger.calls))
	}
}

func TestEnqueueLifecycleEmailsPropagatesOutboxFailureForCallerRollback(t *testing.T) {
	wantErr := errors.New("outbox insert failed")
	store := &fakeEmailEnqueuer{failAt: 2, err: wantErr}
	messages := []dispatch.Message{
		{To: "first@example.test", Subject: "One", HTML: "<p>one</p>", Text: "one"},
		{To: "second@example.test", Subject: "Two", HTML: "<p>two</p>", Text: "two"},
		{To: "third@example.test", Subject: "Three", HTML: "<p>three</p>", Text: "three"},
	}

	err := enqueueLifecycleEmails(context.Background(), store, messages)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want wrapped outbox failure", err)
	}
	if len(store.calls) != 2 {
		t.Fatalf("outbox calls = %d, want stop at failed insert", len(store.calls))
	}
	if store.calls[0].ToEmail != messages[0].To || store.calls[0].Subject != messages[0].Subject {
		t.Fatalf("first outbox row = %#v, want rendered first message", store.calls[0])
	}
}

func TestUsesDurableEmailQueueOnlyForQueueingMailer(t *testing.T) {
	if !usesDurableEmailQueue(dispatch.QueueingMailer{}) {
		t.Fatal("QueueingMailer must use the transactional outbox")
	}
	if usesDurableEmailQueue(dispatch.NoopMailer{}) {
		t.Fatal("non-queue test mailer should retain post-commit adapter behavior")
	}
}

func TestRetainSendEvidenceCoversPDFSourceAndFailsClosed(t *testing.T) {
	wantErr := errors.New("object lock unavailable")
	retainer := &fakeEvidenceRetainer{failAt: 2, err: wantErr}
	retainUntil := time.Date(2033, time.January, 2, 3, 4, 5, 0, time.UTC)
	doc := &generated.Document{
		ID:                          uuid.New(),
		SourceKind:                  "pdf",
		RequiresSignature:           true,
		PdfStorageKey:               pgtype.Text{String: "source.pdf", Valid: true},
		PdfSha256:                   make([]byte, sha256.Size),
		PdfStorageVersionID:         pgtype.Text{String: "version-source", Valid: true},
		RenderedPdfKey:              pgtype.Text{String: "rendered.pdf", Valid: true},
		RenderedPdfSha:              make([]byte, sha256.Size),
		RenderedPdfVersionID:        pgtype.Text{String: "version-rendered", Valid: true},
		EvidenceVersionPinsRequired: true,
	}

	err := retainSendEvidence(context.Background(), retainer, doc, retainUntil)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want wrapped retention failure", err)
	}
	if len(retainer.calls) != 2 || retainer.calls[0] != "source.pdf" || retainer.calls[1] != "rendered.pdf" {
		t.Fatalf("retention calls = %#v, want both PDF artifacts", retainer.calls)
	}
	for i, got := range retainer.retainUntil {
		if !got.Equal(retainUntil) {
			t.Fatalf("retention call %d deadline = %s, want durable %s", i, got, retainUntil)
		}
	}
	if err := retainSendEvidence(context.Background(), nil, doc, retainUntil); err == nil {
		t.Fatal("evidence-bearing document should fail when retention is unavailable")
	}
}

func TestCanonicalSendSealingRetainUntilRequiresExactCeremonyDeadline(t *testing.T) {
	epoch := time.Date(2028, time.February, 29, 12, 34, 56, 123_456_000, time.FixedZone("source", 2*60*60))
	want := storage.EvidenceRetentionDeadline(epoch, article13.RetentionYearsV1)
	valid := &generated.SendSealingIntent{
		Article13NoticeEpochAt: pgtype.Timestamptz{Time: epoch, Valid: true},
		RetainUntil:            pgtype.Timestamptz{Time: want, Valid: true},
	}

	got, err := canonicalSendSealingRetainUntil(valid)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Fatalf("deadline = %s, want %s", got, want)
	}

	wrong := want.Add(time.Second)
	for _, test := range []struct {
		name   string
		intent *generated.SendSealingIntent
	}{
		{name: "nil intent"},
		{name: "missing epoch", intent: &generated.SendSealingIntent{RetainUntil: valid.RetainUntil}},
		{name: "missing deadline", intent: &generated.SendSealingIntent{Article13NoticeEpochAt: valid.Article13NoticeEpochAt}},
		{name: "fractional deadline", intent: &generated.SendSealingIntent{
			Article13NoticeEpochAt: valid.Article13NoticeEpochAt,
			RetainUntil:            pgtype.Timestamptz{Time: want.Add(time.Nanosecond), Valid: true},
		}},
		{name: "wrong whole-second deadline", intent: &generated.SendSealingIntent{
			Article13NoticeEpochAt: valid.Article13NoticeEpochAt,
			RetainUntil:            pgtype.Timestamptz{Time: wrong, Valid: true},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := canonicalSendSealingRetainUntil(test.intent); err == nil {
				t.Fatal("invalid ceremony retention commitment was accepted")
			}
		})
	}
}

type fakeAuditAppender struct {
	calls  []audit.Entry
	failAt int
	err    error
}

func (f *fakeAuditAppender) LogTx(_ context.Context, _ pgx.Tx, entry audit.Entry) (audit.PendingEvent, error) {
	f.calls = append(f.calls, entry)
	if f.failAt > 0 && len(f.calls) == f.failAt {
		return audit.PendingEvent{}, f.err
	}
	return audit.PendingEvent{ID: uuid.New(), Entry: entry}, nil
}

type fakeEmailEnqueuer struct {
	calls  []generated.EnqueueEmailDeliveryParams
	failAt int
	err    error
}

type fakeEvidenceRetainer struct {
	calls       []string
	retainUntil []time.Time
	failAt      int
	err         error
}

func (f *fakeEvidenceRetainer) RetainEvidenceVersion(_ context.Context, key, _ string, _ []byte, retainUntil time.Time) error {
	f.calls = append(f.calls, key)
	f.retainUntil = append(f.retainUntil, retainUntil)
	if f.failAt > 0 && len(f.calls) == f.failAt {
		return f.err
	}
	return nil
}

func (*fakeEvidenceRetainer) GetVerifiedVersion(context.Context, string, string, []byte) ([]byte, error) {
	return nil, nil
}

func (*fakeEvidenceRetainer) ResolveVerifiedLegacy(_ context.Context, _ string, expected []byte) ([]byte, storage.StoredObject, error) {
	ref := storage.StoredObject{VersionID: "version-legacy"}
	copy(ref.SHA256[:], expected)
	return nil, ref, nil
}

func (f *fakeEmailEnqueuer) EnqueueEmailDelivery(_ context.Context, arg generated.EnqueueEmailDeliveryParams) (*generated.EmailDelivery, error) {
	f.calls = append(f.calls, arg)
	if f.failAt > 0 && len(f.calls) == f.failAt {
		return nil, f.err
	}
	return &generated.EmailDelivery{ID: uuid.New(), ToEmail: arg.ToEmail}, nil
}
