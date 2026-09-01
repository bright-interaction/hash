// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

type purgeDeleterStub struct {
	err   error
	key   string
	calls int
}

func (s *purgeDeleterStub) Delete(_ context.Context, key string) error {
	s.calls++
	s.key = key
	return s.err
}

func TestPurgeOwnedSourceKeyPreservesSharedAndEvidenceObjects(t *testing.T) {
	source := pgtype.Text{String: "org/o/documents/source.pdf", Valid: true}
	tests := []struct {
		name string
		doc  *generated.Document
		want string
	}{
		{"owned draft", &generated.Document{Status: "draft", PdfStorageKey: source}, source.String},
		{"template clone", &generated.Document{Status: "draft", TemplateID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PdfStorageKey: source}, ""},
		{"final alias", &generated.Document{Status: "draft", PdfStorageKey: source, FinalPdfKey: source}, ""},
		{"audit alias", &generated.Document{Status: "draft", PdfStorageKey: source, AuditCertKey: source}, ""},
		{"terminal", &generated.Document{Status: "completed", PdfStorageKey: source}, ""},
		{"blocks draft", &generated.Document{Status: "draft"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := purgeOwnedSourceKey(tt.doc); got != tt.want {
				t.Fatalf("purgeOwnedSourceKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCleanupClaimedSoftDeletedDocument_RetriesStorageBeforeDeletingRow(t *testing.T) {
	doc := &generated.Document{
		Status:        "draft",
		PdfStorageKey: pgtype.Text{String: "org/o/documents/source.pdf", Valid: true},
	}
	storageErr := errors.New("object store unavailable")
	objects := &purgeDeleterStub{err: storageErr}
	rowDeletes := 0
	rows, err := cleanupClaimedSoftDeletedDocument(context.Background(), doc, objects, func(context.Context, *generated.Document) (int64, error) {
		rowDeletes++
		return 1, nil
	})
	if !errors.Is(err, storageErr) || rows != 0 {
		t.Fatalf("cleanup result = rows %d, err %v", rows, err)
	}
	if rowDeletes != 0 {
		t.Fatal("DB row must remain when source-object cleanup fails")
	}

	objects.err = nil
	rows, err = cleanupClaimedSoftDeletedDocument(context.Background(), doc, objects, func(context.Context, *generated.Document) (int64, error) {
		rowDeletes++
		return 1, nil
	})
	if err != nil || rows != 1 || rowDeletes != 1 {
		t.Fatalf("retry result = rows %d, deletes %d, err %v", rows, rowDeletes, err)
	}
	if objects.key != doc.PdfStorageKey.String {
		t.Fatalf("deleted key = %q", objects.key)
	}
}

func TestCleanupClaimedSoftDeletedDocument_PreservesSharedSourceWithoutStorage(t *testing.T) {
	doc := &generated.Document{
		Status:        "draft",
		TemplateID:    pgtype.UUID{Bytes: uuid.New(), Valid: true},
		PdfStorageKey: pgtype.Text{String: "templates/shared.pdf", Valid: true},
	}
	rowDeletes := 0
	rows, err := cleanupClaimedSoftDeletedDocument(context.Background(), doc, nil, func(context.Context, *generated.Document) (int64, error) {
		rowDeletes++
		return 1, nil
	})
	if err != nil || rows != 1 || rowDeletes != 1 {
		t.Fatalf("shared-source cleanup = rows %d, deletes %d, err %v", rows, rowDeletes, err)
	}
}
