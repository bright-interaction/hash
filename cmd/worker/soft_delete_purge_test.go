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
	err       error
	key       string
	versionID string
	digest    []byte
	calls     int
}

func (s *purgeDeleterStub) DeleteVersion(_ context.Context, key, versionID string, digest []byte) error {
	s.calls++
	s.key = key
	s.versionID = versionID
	s.digest = append([]byte(nil), digest...)
	return s.err
}

func TestPurgeOwnedSourceVersionPreservesSharedAndEvidenceObjects(t *testing.T) {
	source := pgtype.Text{String: "org/o/documents/source.pdf", Valid: true}
	tests := []struct {
		name string
		doc  *generated.Document
		want bool
	}{
		{"owned draft", &generated.Document{Status: "draft", PdfStorageKey: source, PdfSha256: make([]byte, 32), PdfStorageVersionID: pgtype.Text{String: "version-1", Valid: true}, EvidenceVersionPinsRequired: true}, true},
		{"template clone", &generated.Document{Status: "draft", TemplateID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PdfStorageKey: source}, false},
		{"final alias", &generated.Document{Status: "draft", PdfStorageKey: source, FinalPdfKey: source}, false},
		{"audit alias", &generated.Document{Status: "draft", PdfStorageKey: source, AuditCertKey: source}, false},
		{"terminal", &generated.Document{Status: "completed", PdfStorageKey: source}, false},
		{"blocks draft", &generated.Document{Status: "draft"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := purgeOwnedSourceVersion(tt.doc)
			if err != nil || (got != nil) != tt.want {
				t.Fatalf("purgeOwnedSourceVersion() = %#v, %v; want present=%v", got, err, tt.want)
			}
		})
	}
	if got, err := purgeOwnedSourceVersion(&generated.Document{Status: "draft", PdfStorageKey: source}); err == nil || got != nil {
		t.Fatalf("unpinned source cleanup = %#v, %v; want fail-closed refusal", got, err)
	}
}

func TestCleanupClaimedSoftDeletedDocument_RetriesStorageBeforeDeletingRow(t *testing.T) {
	doc := &generated.Document{
		Status: "draft", PdfStorageKey: pgtype.Text{String: "org/o/documents/source.pdf", Valid: true},
		PdfSha256: make([]byte, 32), PdfStorageVersionID: pgtype.Text{String: "version-1", Valid: true},
		EvidenceVersionPinsRequired: true,
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
	if objects.versionID != doc.PdfStorageVersionID.String || len(objects.digest) != 32 {
		t.Fatalf("deleted identity = %q/%d", objects.versionID, len(objects.digest))
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
