// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

type cleanupDeleterStub struct {
	key       string
	versionID string
	digest    []byte
	ctxErr    error
}

func (s *cleanupDeleterStub) DeleteVersion(ctx context.Context, key, versionID string, digest []byte) error {
	s.key = key
	s.versionID = versionID
	s.digest = append([]byte(nil), digest...)
	s.ctxErr = ctx.Err()
	return nil
}

func TestDeleteObjectDetachedIgnoresRequestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st := &cleanupDeleterStub{}
	if err := deleteObjectDetached(ctx, st, cleanupObjectVersion{
		Key: "org/test/documents/source.pdf", VersionID: "version-1", SHA256: make([]byte, 32),
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if st.key == "" || st.versionID != "version-1" || len(st.digest) != 32 || st.ctxErr != nil {
		t.Fatalf("cleanup identity/context = %q/%q/%d/%v", st.key, st.versionID, len(st.digest), st.ctxErr)
	}
}

func TestDraftSourceObjectKeysPreservesSharedAndLegalPDFs(t *testing.T) {
	source := pgtype.Text{String: "org/o/documents/upload.pdf", Valid: true}

	ownedDraft := &generated.Document{
		Status: "draft", PdfStorageKey: source, PdfSha256: make([]byte, 32),
		PdfStorageVersionID: pgtype.Text{String: "version-1", Valid: true}, EvidenceVersionPinsRequired: true,
	}
	if got, err := draftSourceObjectVersions(ownedDraft); err != nil || len(got) != 1 || got[0].Key != source.String {
		t.Fatalf("owned draft versions = %v, %v; want source", got, err)
	}

	templated := &generated.Document{
		Status:        "draft",
		TemplateID:    pgtype.UUID{Bytes: uuid.New(), Valid: true},
		PdfStorageKey: source,
	}
	if got, err := draftSourceObjectVersions(templated); err != nil || len(got) != 0 {
		t.Fatalf("shared template source must be preserved, got %v", got)
	}

	completed := &generated.Document{
		Status:        "completed",
		PdfStorageKey: source,
		FinalPdfKey:   source,
	}
	if got, err := draftSourceObjectVersions(completed); err != nil || len(got) != 0 {
		t.Fatalf("completed evidence must be preserved, got %v", got)
	}

	draftWithLegalAlias := &generated.Document{
		Status:        "draft",
		PdfStorageKey: source,
		FinalPdfKey:   source,
	}
	if got, err := draftSourceObjectVersions(draftWithLegalAlias); err != nil || len(got) != 0 {
		t.Fatalf("source aliased by final evidence must be preserved, got %v", got)
	}

	unpinned := &generated.Document{Status: "draft", PdfStorageKey: source, PdfSha256: make([]byte, 32)}
	if got, err := draftSourceObjectVersions(unpinned); err == nil || len(got) != 0 {
		t.Fatalf("unpinned draft cleanup = %v, %v; want fail-closed refusal", got, err)
	}
}
