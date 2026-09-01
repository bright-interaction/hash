// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	pdfmodel "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
)

func TestValidateAcknowledgementSendRequiresStandalonePDFEvidence(t *testing.T) {
	base := generated.Document{
		ID:                uuid.New(),
		SourceKind:        "pdf",
		RoutingTier:       "SES",
		RequiresSignature: false,
		PdfStorageKey:     pgtype.Text{String: "org/document/source.pdf", Valid: true},
		PdfSha256:         make([]byte, 32),
	}
	clone := func() *generated.Document {
		doc := base
		doc.PdfSha256 = append([]byte(nil), base.PdfSha256...)
		return &doc
	}

	tests := []struct {
		name   string
		mutate func(*generated.Document)
		want   error
	}{
		{name: "valid standalone PDF", want: nil},
		{name: "blocks acknowledgement", mutate: func(d *generated.Document) { d.SourceKind = "blocks" }, want: ErrAcknowledgementNeedsPDF},
		{name: "missing source key", mutate: func(d *generated.Document) { d.PdfStorageKey = pgtype.Text{} }, want: ErrAcknowledgementNeedsPDF},
		{name: "blank source key", mutate: func(d *generated.Document) { d.PdfStorageKey.String = "  " }, want: ErrAcknowledgementNeedsPDF},
		{name: "missing digest", mutate: func(d *generated.Document) { d.PdfSha256 = nil }, want: ErrAcknowledgementNeedsPDF},
		{name: "malformed digest", mutate: func(d *generated.Document) { d.PdfSha256 = []byte{1} }, want: ErrAcknowledgementNeedsPDF},
		{name: "attached child", mutate: func(d *generated.Document) { d.ParentEnvelopeID = pgtype.UUID{Bytes: uuid.New(), Valid: true} }, want: ErrAcknowledgementNeedsPDF},
		{name: "envelope wrapper", mutate: func(d *generated.Document) { d.IsEnvelope = true }, want: ErrEnvelopeRequiresSignature},
		{name: "signature ceremony unaffected", mutate: func(d *generated.Document) {
			d.RequiresSignature = true
			d.SourceKind = "blocks"
			d.PdfStorageKey = pgtype.Text{}
			d.PdfSha256 = nil
		}, want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := clone()
			if tc.mutate != nil {
				tc.mutate(doc)
			}
			err := validateAcknowledgementSend(doc)
			if tc.want == nil && err != nil {
				t.Fatalf("validateAcknowledgementSend() error = %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("validateAcknowledgementSend() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestValidatePDFSignatureFieldsRequiresPlacedFieldForSoleSigner(t *testing.T) {
	docID := uuid.New()
	signerID := uuid.New()
	approverID := uuid.New()
	ccID := uuid.New()
	doc := &generated.Document{ID: docID, SourceKind: "pdf", RequiresSignature: true}
	recipients := []*generated.Recipient{
		{ID: signerID, DocumentID: docID, Role: "signer", Status: "pending"},
		{ID: approverID, DocumentID: docID, Role: "approver", Status: "pending"},
		{ID: ccID, DocumentID: docID, Role: "cc", Status: "pending"},
	}
	field := func(owner uuid.UUID) *generated.DocumentField {
		return &generated.DocumentField{
			ID:          uuid.New(),
			DocumentID:  docID,
			RecipientID: pgtype.UUID{Bytes: owner, Valid: true},
			Type:        "signature",
			Page:        1,
			XPct:        testNumeric(10),
			YPct:        testNumeric(20),
			WPct:        testNumeric(25),
			HPct:        testNumeric(8),
			Required:    true,
		}
	}

	if err := validatePDFSignatureFields(doc, recipients, []*generated.DocumentField{field(signerID)}, 1); err != nil {
		t.Fatalf("valid PDF signature field rejected: %v", err)
	}

	tests := []struct {
		name   string
		fields func() []*generated.DocumentField
	}{
		{name: "missing", fields: func() []*generated.DocumentField { return nil }},
		{name: "only non-signature field", fields: func() []*generated.DocumentField {
			f := field(signerID)
			f.Type = "text"
			return []*generated.DocumentField{f}
		}},
		{name: "assigned to approver", fields: func() []*generated.DocumentField { return []*generated.DocumentField{field(approverID)} }},
		{name: "assigned to cc", fields: func() []*generated.DocumentField { return []*generated.DocumentField{field(ccID)} }},
		{name: "unassigned", fields: func() []*generated.DocumentField {
			f := field(signerID)
			f.RecipientID = pgtype.UUID{}
			return []*generated.DocumentField{f}
		}},
		{name: "optional", fields: func() []*generated.DocumentField {
			f := field(signerID)
			f.Required = false
			return []*generated.DocumentField{f}
		}},
		{name: "invalid page", fields: func() []*generated.DocumentField {
			f := field(signerID)
			f.Page = 0
			return []*generated.DocumentField{f}
		}},
		{name: "page beyond retained source", fields: func() []*generated.DocumentField {
			f := field(signerID)
			f.Page = 2
			return []*generated.DocumentField{f}
		}},
		{name: "required text unassigned", fields: func() []*generated.DocumentField {
			f := field(signerID)
			f.Type = "text"
			f.RecipientID = pgtype.UUID{}
			return []*generated.DocumentField{field(signerID), f}
		}},
		{name: "required text assigned to cc", fields: func() []*generated.DocumentField {
			f := field(ccID)
			f.Type = "text"
			return []*generated.DocumentField{field(signerID), f}
		}},
		{name: "optional text beyond retained source", fields: func() []*generated.DocumentField {
			f := field(signerID)
			f.Type = "text"
			f.Required = false
			f.Page = 2
			return []*generated.DocumentField{field(signerID), f}
		}},
		{name: "optional text unassigned", fields: func() []*generated.DocumentField {
			f := field(signerID)
			f.Type = "text"
			f.Required = false
			f.RecipientID = pgtype.UUID{}
			return []*generated.DocumentField{field(signerID), f}
		}},
		{name: "optional text assigned to cc", fields: func() []*generated.DocumentField {
			f := field(ccID)
			f.Type = "text"
			f.Required = false
			return []*generated.DocumentField{field(signerID), f}
		}},
		{name: "zero width", fields: func() []*generated.DocumentField {
			f := field(signerID)
			f.WPct = testNumeric(0)
			return []*generated.DocumentField{f}
		}},
		{name: "outside page", fields: func() []*generated.DocumentField {
			f := field(signerID)
			f.XPct = testNumeric(90)
			f.WPct = testNumeric(20)
			return []*generated.DocumentField{f}
		}},
		{name: "invalid numeric", fields: func() []*generated.DocumentField {
			f := field(signerID)
			f.HPct = pgtype.Numeric{}
			return []*generated.DocumentField{f}
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePDFSignatureFields(doc, recipients, tc.fields(), 1)
			if !errors.Is(err, ErrInvalidPDFSignatureField) {
				t.Fatalf("validatePDFSignatureFields() error = %v, want ErrInvalidPDFSignatureField", err)
			}
		})
	}
}

func TestRetainReadySendEvidenceMakesNoRetentionCallForInvalidPDF(t *testing.T) {
	docID := uuid.New()
	signerID := uuid.New()
	doc := &generated.Document{
		ID: docID, SourceKind: "pdf", RequiresSignature: true,
		PdfStorageKey:               pgtype.Text{String: "org/doc/source.pdf", Valid: true},
		PdfSha256:                   make([]byte, sha256.Size),
		PdfStorageVersionID:         pgtype.Text{String: "version-source", Valid: true},
		EvidenceVersionPinsRequired: true,
	}
	recipients := []*generated.Recipient{{ID: signerID, DocumentID: docID, Role: "signer", Status: "pending"}}
	field := &generated.DocumentField{
		ID: uuid.New(), DocumentID: docID, RecipientID: pgtype.UUID{Bytes: signerID, Valid: true},
		Type: "signature", Page: 2, XPct: testNumeric(10), YPct: testNumeric(10),
		WPct: testNumeric(20), HPct: testNumeric(8), Required: true,
	}
	retainer := &fakeEvidenceRetainer{}
	retainUntil := time.Date(2033, time.January, 2, 3, 4, 5, 0, time.UTC)
	err := retainReadySendEvidence(context.Background(), retainer, doc, recipients, []*generated.DocumentField{field}, 1, retainUntil)
	if !errors.Is(err, ErrInvalidPDFSignatureField) {
		t.Fatalf("invalid readiness error = %v", err)
	}
	if len(retainer.calls) != 0 {
		t.Fatalf("invalid send made irreversible retention calls: %v", retainer.calls)
	}

	field.Page = 1
	if err := retainReadySendEvidence(context.Background(), retainer, doc, recipients, []*generated.DocumentField{field}, 1, retainUntil); err != nil {
		t.Fatalf("valid readiness rejected: %v", err)
	}
	if len(retainer.calls) != 1 || retainer.calls[0] != doc.PdfStorageKey.String {
		t.Fatalf("valid send retention calls = %v", retainer.calls)
	}
	if len(retainer.retainUntil) != 1 || !retainer.retainUntil[0].Equal(retainUntil) {
		t.Fatalf("valid send retention deadline = %v, want %s", retainer.retainUntil, retainUntil)
	}
}

func TestAcknowledgementFieldsFailClosedBeforeRetention(t *testing.T) {
	doc := &generated.Document{
		ID: uuid.New(), SourceKind: "pdf", RequiresSignature: false,
		PdfStorageKey: pgtype.Text{String: "org/doc/source.pdf", Valid: true},
		PdfSha256:     make([]byte, sha256.Size),
	}
	retainer := &fakeEvidenceRetainer{}
	fields := []*generated.DocumentField{{ID: uuid.New(), DocumentID: doc.ID, Type: "text"}}
	err := retainReadySendEvidence(context.Background(), retainer, doc, nil, fields, 1, time.Date(2033, time.January, 2, 3, 4, 5, 0, time.UTC))
	if !errors.Is(err, ErrAcknowledgementFields) {
		t.Fatalf("acknowledgement field error = %v, want ErrAcknowledgementFields", err)
	}
	if len(retainer.calls) != 0 {
		t.Fatalf("invalid acknowledgement made irreversible retention calls: %v", retainer.calls)
	}
}

func TestSendSealingNeverRevertsOnceRetentionMayHaveStarted(t *testing.T) {
	if !sendSealingReversible(&generated.SendSealingIntent{}) {
		t.Fatal("fresh pre-retention intent must be safely reversible")
	}
	started := &generated.SendSealingIntent{RetentionStartedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}}
	if sendSealingReversible(started) {
		t.Fatal("started retention must never revert to draft")
	}
	completed := &generated.SendSealingIntent{RetentionCompletedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}}
	if sendSealingReversible(completed) {
		t.Fatal("completed retention must never revert to draft after a commit failure")
	}
	if sendSealingReversible(nil) {
		t.Fatal("missing intent must fail closed")
	}
}

type fakePDFEvidenceStorage struct {
	body []byte
	err  error
}

func (f *fakePDFEvidenceStorage) RetainEvidenceVersion(context.Context, string, string, []byte, time.Time) error {
	return f.err
}
func (f *fakePDFEvidenceStorage) GetVerifiedVersion(context.Context, string, string, []byte) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]byte(nil), f.body...), nil
}
func (f *fakePDFEvidenceStorage) ResolveVerifiedLegacy(_ context.Context, _ string, expected []byte) ([]byte, storage.StoredObject, error) {
	if f.err != nil {
		return nil, storage.StoredObject{}, f.err
	}
	ref := storage.StoredObject{VersionID: "version-legacy"}
	copy(ref.SHA256[:], expected)
	return append([]byte(nil), f.body...), ref, nil
}

func TestInspectSendSourcePDFBindsDigestAndPageCount(t *testing.T) {
	pdf := onePageSendPDF(t)
	sum := sha256.Sum256(pdf)
	doc := &generated.Document{
		SourceKind:    "pdf",
		PdfStorageKey: pgtype.Text{String: "org/doc/source.pdf", Valid: true},
		PdfSha256:     sum[:],
	}
	pages, err := inspectSendSourcePDF(context.Background(), &fakePDFEvidenceStorage{body: pdf}, doc)
	if err != nil {
		t.Fatalf("inspectSendSourcePDF() error = %v", err)
	}
	if pages != 1 {
		t.Fatalf("inspectSendSourcePDF() pages = %d, want 1", pages)
	}

	doc.PdfSha256 = make([]byte, sha256.Size)
	if _, err := inspectSendSourcePDF(context.Background(), &fakePDFEvidenceStorage{body: pdf}, doc); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("digest mismatch error = %v", err)
	}
}

func onePageSendPDF(t *testing.T) []byte {
	t.Helper()
	conf := pdfmodel.NewDefaultConfiguration()
	conf.ValidationMode = pdfmodel.ValidationRelaxed
	spec := fmt.Sprintf(`{"pages":{"1":{"mediaBox":"A4","content":{"text":[{"value":%q,"position":[100,700],"font":{"name":"Helvetica","size":12}}]}}}}`, "Hash send readiness")
	var out bytes.Buffer
	if err := pdfapi.Create(nil, strings.NewReader(spec), &out, conf); err != nil {
		t.Fatalf("create one-page PDF: %v", err)
	}
	return out.Bytes()
}

func testNumeric(value int64) pgtype.Numeric {
	return pgtype.Numeric{Int: big.NewInt(value), Valid: true}
}
