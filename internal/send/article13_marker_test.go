// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestDocumentSentAuditEntryCommitsCurrentArticle13RequirementAndAuthoritativeEpoch(t *testing.T) {
	engine := &Engine{}
	actor := Actor{OrgID: uuid.New(), Via: "worker"}
	documentID := uuid.New()
	sentAt := time.Date(2026, 8, 31, 12, 34, 56, 123456000, time.FixedZone("CEST", 2*60*60))
	document := &generated.Document{
		ID: documentID, OrgID: actor.OrgID, Status: "sent",
		SentAt:                           pgtype.Timestamptz{Time: sentAt, Valid: true},
		Article13NoticeEpochAt:           pgtype.Timestamptz{Time: sentAt, Valid: true},
		Article13NoticeSchema:            article13.CurrentSchema,
		Article13NoticeEpochV61Committed: true,
	}
	input := map[string]any{
		"propagated":                           true,
		article13.AuditRequiredNoticeSchemaKey: "stale-or-conflicting-value",
		article13.AuditRequiredNoticeSentAtKey: "1900-01-01T00:00:00Z",
	}

	entry, err := engine.documentSentAuditEntry(actor, document, input)
	if err != nil {
		t.Fatal(err)
	}
	if got := entry.Payload[article13.AuditRequiredNoticeSchemaKey]; got != article13.CurrentSchema {
		t.Fatalf("document.sent marker = %#v, want %q", got, article13.CurrentSchema)
	}
	if got := entry.Payload[article13.AuditRequiredNoticeSentAtKey]; got != "2026-08-31T10:34:56.123456Z" {
		t.Fatalf("document.sent epoch = %#v, want authoritative canonical sent_at", got)
	}
	if got := input[article13.AuditRequiredNoticeSchemaKey]; got != "stale-or-conflicting-value" {
		t.Fatalf("auditEntry mutated caller payload marker to %#v", got)
	}
	if got := input[article13.AuditRequiredNoticeSentAtKey]; got != "1900-01-01T00:00:00Z" {
		t.Fatalf("documentSentAuditEntry mutated caller epoch to %#v", got)
	}
	if entry.DocumentID == nil || *entry.DocumentID != documentID || entry.RecipientID != nil {
		t.Fatalf("document.sent identities = document %#v recipient %#v", entry.DocumentID, entry.RecipientID)
	}

	other := engine.auditEntry(actor, &documentID, nil, audit.KindDocumentCreated, nil)
	if _, present := other.Payload[article13.AuditRequiredNoticeSchemaKey]; present {
		t.Fatal("non-send audit entry unexpectedly carries the Article 13 cutover marker")
	}
	if _, present := other.Payload[article13.AuditRequiredNoticeSentAtKey]; present {
		t.Fatal("non-send audit entry unexpectedly carries the Article 13 epoch marker")
	}
	unsafeGeneric := engine.auditEntry(actor, &documentID, nil, audit.KindDocumentSent, nil)
	if _, present := unsafeGeneric.Payload[article13.AuditRequiredNoticeSchemaKey]; present {
		t.Fatal("generic audit entry manufactured a partial Article 13 send marker")
	}
}

func TestDocumentSentAuditEntryRejectsUncommittedOrMismatchedRows(t *testing.T) {
	engine := &Engine{}
	actor := Actor{OrgID: uuid.New()}
	valid := &generated.Document{
		ID: uuid.New(), OrgID: actor.OrgID, Status: "sent",
		SentAt:                           pgtype.Timestamptz{Time: time.Now(), Valid: true},
		Article13NoticeSchema:            article13.CurrentSchema,
		Article13NoticeEpochV61Committed: true,
	}
	valid.Article13NoticeEpochAt = valid.SentAt
	for _, document := range []*generated.Document{
		nil,
		{ID: valid.ID, OrgID: valid.OrgID, Status: "sealing", SentAt: valid.SentAt, Article13NoticeEpochAt: valid.Article13NoticeEpochAt, Article13NoticeSchema: valid.Article13NoticeSchema, Article13NoticeEpochV61Committed: true},
		{ID: valid.ID, OrgID: uuid.New(), Status: "sent", SentAt: valid.SentAt, Article13NoticeEpochAt: valid.Article13NoticeEpochAt, Article13NoticeSchema: valid.Article13NoticeSchema, Article13NoticeEpochV61Committed: true},
		{ID: valid.ID, OrgID: valid.OrgID, Status: "sent"},
		{ID: valid.ID, OrgID: valid.OrgID, Status: "sent", SentAt: valid.SentAt, Article13NoticeEpochAt: pgtype.Timestamptz{Time: valid.SentAt.Time.Add(time.Microsecond), Valid: true}, Article13NoticeSchema: valid.Article13NoticeSchema, Article13NoticeEpochV61Committed: true},
		{ID: valid.ID, OrgID: valid.OrgID, Status: "sent", SentAt: valid.SentAt, Article13NoticeEpochAt: valid.Article13NoticeEpochAt, Article13NoticeSchema: "hash-a13-future", Article13NoticeEpochV61Committed: true},
		{ID: valid.ID, OrgID: valid.OrgID, Status: "sent", SentAt: valid.SentAt, Article13NoticeEpochAt: valid.Article13NoticeEpochAt, Article13NoticeSchema: valid.Article13NoticeSchema},
	} {
		if _, err := engine.documentSentAuditEntry(actor, document, nil); err == nil {
			t.Fatalf("documentSentAuditEntry(%#v) succeeded", document)
		}
	}
}

func TestCompletedSendSealingStatusRequiresDurableSendProof(t *testing.T) {
	sentAt := time.Date(2026, 8, 31, 12, 34, 56, 123456000, time.UTC)
	valid := generated.Document{
		Status:                           "sent",
		SentAt:                           pgtype.Timestamptz{Time: sentAt, Valid: true},
		Article13NoticeEpochAt:           pgtype.Timestamptz{Time: sentAt, Valid: true},
		Article13NoticeSchema:            article13.CurrentSchema,
		Article13NoticeEpochV61Committed: true,
		EvidenceVersionPinsRequired:      true,
	}
	for _, status := range []string{
		"sent", "in_progress", "changes_requested", "finalizing",
		"completed", "declined", "voided", "expired",
	} {
		document := valid
		document.Status = status
		result, ok := completedSendSealingStatus(&document)
		if !ok || result.Status != status || len(result.Links) != 0 {
			t.Fatalf("completedSendSealingStatus(%q) = %#v/%t", status, result, ok)
		}
	}

	missingSentAt := valid
	missingSentAt.SentAt = pgtype.Timestamptz{}
	mismatchedEpoch := valid
	mismatchedEpoch.Article13NoticeEpochAt.Time = sentAt.Add(time.Microsecond)
	unsupportedSchema := valid
	unsupportedSchema.Article13NoticeSchema = "hash-a13-future"
	uncommitted := valid
	uncommitted.Article13NoticeEpochV61Committed = false
	unpinned := valid
	unpinned.EvidenceVersionPinsRequired = false
	revisedDraft := valid
	revisedDraft.Status = "draft"
	for _, document := range []*generated.Document{
		nil, &missingSentAt, &mismatchedEpoch, &unsupportedSchema,
		&uncommitted, &unpinned, &revisedDraft,
	} {
		if result, ok := completedSendSealingStatus(document); ok {
			t.Fatalf("corrupt or non-descendant document converged as %#v", result)
		}
	}
}
