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
	key    string
	ctxErr error
}

func (s *cleanupDeleterStub) Delete(ctx context.Context, key string) error {
	s.key = key
	s.ctxErr = ctx.Err()
	return nil
}

func TestDeleteObjectDetachedIgnoresRequestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st := &cleanupDeleterStub{}
	if err := deleteObjectDetached(ctx, st, "org/test/documents/source.pdf"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if st.key == "" || st.ctxErr != nil {
		t.Fatalf("cleanup key/context = %q/%v", st.key, st.ctxErr)
	}
}

func TestDraftSourceObjectKeysPreservesSharedAndLegalPDFs(t *testing.T) {
	source := pgtype.Text{String: "org/o/documents/upload.pdf", Valid: true}

	ownedDraft := &generated.Document{Status: "draft", PdfStorageKey: source}
	if got := draftSourceObjectKeys(ownedDraft); len(got) != 1 || got[0] != source.String {
		t.Fatalf("owned draft keys = %v, want source", got)
	}

	templated := &generated.Document{
		Status:        "draft",
		TemplateID:    pgtype.UUID{Bytes: uuid.New(), Valid: true},
		PdfStorageKey: source,
	}
	if got := draftSourceObjectKeys(templated); len(got) != 0 {
		t.Fatalf("shared template source must be preserved, got %v", got)
	}

	completed := &generated.Document{
		Status:        "completed",
		PdfStorageKey: source,
		FinalPdfKey:   source,
	}
	if got := draftSourceObjectKeys(completed); len(got) != 0 {
		t.Fatalf("completed evidence must be preserved, got %v", got)
	}

	draftWithLegalAlias := &generated.Document{
		Status:        "draft",
		PdfStorageKey: source,
		FinalPdfKey:   source,
	}
	if got := draftSourceObjectKeys(draftWithLegalAlias); len(got) != 0 {
		t.Fatalf("source aliased by final evidence must be preserved, got %v", got)
	}
}
