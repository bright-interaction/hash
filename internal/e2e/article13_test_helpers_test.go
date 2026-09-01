// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e || demo

package e2e

import (
	"reflect"
	"testing"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/sign"
)

func testArticle13NoticeEvidence(t testing.TB, rc *sign.RecipientContext) sign.Article13NoticeEvidence {
	t.Helper()
	if rc == nil || rc.Document == nil || rc.Recipient == nil || !rc.Document.SentAt.Valid {
		t.Fatal("Article 13 test evidence requires a recipient context with sent_at")
	}
	snapshot, err := article13.NewSnapshot(article13.Input{
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
