// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// testArticle13NoticeEvidence supplies a complete notice bound to rc so tests
// that target a later validation or transactional branch cannot pass merely
// because the public engine rejected an empty notice first.
func testArticle13NoticeEvidence(t testing.TB, rc *RecipientContext) Article13NoticeEvidence {
	t.Helper()
	if rc == nil || rc.Document == nil || rc.Recipient == nil || !rc.Document.SentAt.Valid {
		t.Fatal("Article 13 test evidence requires a recipient context with sent_at")
	}
	// Production rows receive these fields from migration 00061's guarded send
	// completion. Keep focused engine fixtures honest without repeating the
	// durable ceremony tuple in every unrelated test.
	rc.Document.Article13NoticeSchema = article13.CurrentSchema
	rc.Document.Article13NoticeEpochAt = rc.Document.SentAt
	snapshot, err := article13.NewSnapshotForSchema(rc.Document.Article13NoticeSchema, article13.Input{
		DocumentID:           rc.Document.ID,
		OrgID:                rc.Document.OrgID,
		RecipientID:          rc.Recipient.ID,
		SentAt:               rc.Document.SentAt.Time,
		Controller:           "Test Controller AB",
		ControllerContact:    "legal@controller.example",
		Processor:            "Test Operator AB",
		ProcessorContact:     "privacy@operator.example",
		PurposeSummary:       "Collect and retain a test document response.",
		LegalBasisDisclosure: "Controller confirmed GDPR Article 6(1)(b).",
		RetentionYears:       article13.RetentionYearsV1,
		SupervisoryAuthority: "Test Data Protection Authority",
		PolicyURL:            "https://operator.example/privacy",
		DSRCapability:        article13.DSRCapabilitySignerRequest,
		Copy:                 testArticle13NoticeCopy(),
	})
	if err != nil {
		t.Fatalf("construct Article 13 test snapshot: %v", err)
	}
	evidence, err := article13.NewEvidence(snapshot)
	if err != nil {
		t.Fatalf("construct Article 13 test evidence: %v", err)
	}
	return evidence
}

func testArticle13NoticeCopy() article13.Copy {
	var copy article13.Copy
	value := reflect.ValueOf(&copy).Elem()
	typeOfCopy := value.Type()
	for i := 0; i < value.NumField(); i++ {
		value.Field(i).SetString("Test " + typeOfCopy.Field(i).Name)
	}
	return copy
}

func TestValidateNoticeEvidenceRejectsInvalidOrCrossCeremonyEvidence(t *testing.T) {
	sentAt := time.Date(2026, 8, 31, 16, 0, 0, 123456000, time.UTC)
	doc := &generated.Document{
		ID: uuid.New(), OrgID: uuid.New(),
		SentAt: pgtype.Timestamptz{Time: sentAt, Valid: true},
	}
	recipient := &generated.GetRecipientByTokenHashRow{ID: uuid.New(), DocumentID: doc.ID, Role: "signer"}
	baseRC := &RecipientContext{Document: doc, Recipient: recipient}
	valid := testArticle13NoticeEvidence(t, baseRC)
	if err := validateNoticeEvidence(baseRC, valid); err != nil {
		t.Fatalf("valid notice evidence rejected: %v", err)
	}

	cloneRC := func() *RecipientContext {
		docCopy := *doc
		recipientCopy := *recipient
		return &RecipientContext{Document: &docCopy, Recipient: &recipientCopy}
	}
	evidenceWithSnapshot := func(snapshot article13.Snapshot) Article13NoticeEvidence {
		t.Helper()
		evidence, err := article13.NewEvidence(snapshot)
		if err != nil {
			t.Fatalf("construct mismatched but internally valid evidence: %v", err)
		}
		return evidence
	}

	badDigest := valid
	badDigest.Digest = "0000000000000000000000000000000000000000000000000000000000000000"
	badSchema := valid
	badSchema.Schema = "hash-a13-unsupported"
	wrongOrgSnapshot := valid.Snapshot
	wrongOrgSnapshot.OrgID = uuid.New()
	wrongDocumentSnapshot := valid.Snapshot
	wrongDocumentSnapshot.DocumentID = uuid.New()
	wrongRecipientSnapshot := valid.Snapshot
	wrongRecipientSnapshot.RecipientID = uuid.New()
	wrongSentAtSnapshot := valid.Snapshot
	wrongSentAtSnapshot.SentAt = sentAt.Add(time.Second).Format(time.RFC3339Nano)
	invalidSentAtRC := cloneRC()
	invalidSentAtRC.Document.SentAt.Valid = false
	invalidEpochRC := cloneRC()
	invalidEpochRC.Document.Article13NoticeEpochAt.Time = sentAt.Add(time.Minute)
	invalidSchemaRC := cloneRC()
	invalidSchemaRC.Document.Article13NoticeSchema = "hash-a13-future"

	tests := []struct {
		name     string
		rc       *RecipientContext
		evidence Article13NoticeEvidence
	}{
		{name: "nil context", rc: nil, evidence: valid},
		{name: "nil document", rc: &RecipientContext{Recipient: recipient}, evidence: valid},
		{name: "nil recipient", rc: &RecipientContext{Document: doc}, evidence: valid},
		{name: "empty evidence", rc: cloneRC(), evidence: Article13NoticeEvidence{}},
		{name: "digest mismatch", rc: cloneRC(), evidence: badDigest},
		{name: "envelope schema mismatch", rc: cloneRC(), evidence: badSchema},
		{name: "organization mismatch", rc: cloneRC(), evidence: evidenceWithSnapshot(wrongOrgSnapshot)},
		{name: "document mismatch", rc: cloneRC(), evidence: evidenceWithSnapshot(wrongDocumentSnapshot)},
		{name: "recipient mismatch", rc: cloneRC(), evidence: evidenceWithSnapshot(wrongRecipientSnapshot)},
		{name: "sent_at mismatch", rc: cloneRC(), evidence: evidenceWithSnapshot(wrongSentAtSnapshot)},
		{name: "invalid context sent_at", rc: invalidSentAtRC, evidence: valid},
		{name: "database epoch mismatch", rc: invalidEpochRC, evidence: valid},
		{name: "active marker schema mismatch", rc: invalidSchemaRC, evidence: valid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateNoticeEvidence(tt.rc, tt.evidence); !errors.Is(err, ErrInvalidNoticeEvidence) {
				t.Fatalf("validateNoticeEvidence() error = %v, want ErrInvalidNoticeEvidence", err)
			}
		})
	}
}

func TestValidateLockedNoticeEvidenceUsesAuthoritativeSentEpoch(t *testing.T) {
	sentAt := time.Date(2026, 8, 31, 17, 0, 0, 0, time.UTC)
	doc := &generated.Document{
		ID: uuid.New(), OrgID: uuid.New(),
		SentAt: pgtype.Timestamptz{Time: sentAt, Valid: true},
	}
	recipient := &generated.GetRecipientByTokenHashRow{ID: uuid.New(), DocumentID: doc.ID, Role: "signer"}
	rc := &RecipientContext{Document: doc, Recipient: recipient}
	evidence := testArticle13NoticeEvidence(t, rc)

	locked := *doc
	if err := ValidateLockedNoticeEvidence(rc, &locked, evidence); err != nil {
		t.Fatalf("matching locked ceremony rejected: %v", err)
	}

	locked.SentAt.Time = sentAt.Add(time.Minute)
	if err := ValidateLockedNoticeEvidence(rc, &locked, evidence); !errors.Is(err, ErrInvalidNoticeEvidence) {
		t.Fatalf("stale pre-resend evidence error = %v, want ErrInvalidNoticeEvidence", err)
	}

	locked = *doc
	locked.ID = uuid.New()
	if err := ValidateLockedNoticeEvidence(rc, &locked, evidence); !errors.Is(err, ErrInvalidNoticeEvidence) {
		t.Fatalf("wrong locked document error = %v, want ErrInvalidNoticeEvidence", err)
	}

	locked = *doc
	locked.OrgID = uuid.New()
	if err := ValidateLockedNoticeEvidence(rc, &locked, evidence); !errors.Is(err, ErrInvalidNoticeEvidence) {
		t.Fatalf("wrong locked organization error = %v, want ErrInvalidNoticeEvidence", err)
	}
}
