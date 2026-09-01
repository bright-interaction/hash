// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package docintake

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
)

type intakeQueriesStub struct {
	createErr error
}

func (s *intakeQueriesStub) CreatePDFDocument(context.Context, generated.CreatePDFDocumentParams) (*generated.Document, error) {
	if s.createErr != nil {
		return nil, s.createErr
	}
	return &generated.Document{ID: uuid.New()}, nil
}

func (*intakeQueriesStub) UpdateMetadataRedactionReport(context.Context, generated.UpdateMetadataRedactionReportParams) error {
	return nil
}

type intakeStoreStub struct {
	putKeys      []string
	deletedKeys  []string
	deleteCtxErr error
	deleteErr    error
}

func (s *intakeStoreStub) PutVersioned(_ context.Context, key, _ string, _ []byte) (storage.StoredObject, error) {
	s.putKeys = append(s.putKeys, key)
	return storage.StoredObject{SHA256: [32]byte{1}, VersionID: "version-intake"}, nil
}

func (s *intakeStoreStub) Delete(ctx context.Context, key string) error {
	s.deletedKeys = append(s.deletedKeys, key)
	s.deleteCtxErr = ctx.Err()
	return s.deleteErr
}

func intakeTestPDF(t *testing.T) []byte {
	t.Helper()
	definition := []byte("{\"pages\":{\"1\":{\"content\":{\"text\":[{\"value\":\"proposal\",\"anchor\":\"center\",\"font\":{\"name\":\"Helvetica\",\"size\":12}}]}}}}")
	var out bytes.Buffer
	if err := pdfapi.Create(nil, bytes.NewReader(definition), &out, model.NewDefaultConfiguration()); err != nil {
		t.Fatalf("create PDF fixture: %v", err)
	}
	return out.Bytes()
}

func TestCreatePDFSourceDocumentDeletesObjectWhenDatabaseInsertFails(t *testing.T) {
	dbErr := errors.New("database unavailable")
	q := &intakeQueriesStub{createErr: dbErr}
	st := &intakeStoreStub{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cleanup must not inherit this cancellation

	_, _, err := CreatePDFSourceDocument(ctx, q, st, uuid.New(), uuid.New(), "Proposal", intakeTestPDF(t))
	if !errors.Is(err, dbErr) {
		t.Fatalf("expected database error, got %v", err)
	}
	if len(st.putKeys) != 1 || len(st.deletedKeys) != 1 {
		t.Fatalf("put/delete calls = %d/%d, want 1/1", len(st.putKeys), len(st.deletedKeys))
	}
	if st.deletedKeys[0] != st.putKeys[0] {
		t.Fatalf("deleted key %q, want uploaded key %q", st.deletedKeys[0], st.putKeys[0])
	}
	if st.deleteCtxErr != nil {
		t.Fatalf("cleanup inherited canceled request context: %v", st.deleteCtxErr)
	}
}

func TestCreatePDFSourceDocumentReportsOrphanCleanupFailure(t *testing.T) {
	dbErr := errors.New("insert failed")
	deleteErr := errors.New("object store unavailable")
	q := &intakeQueriesStub{createErr: dbErr}
	st := &intakeStoreStub{deleteErr: deleteErr}

	_, _, err := CreatePDFSourceDocument(context.Background(), q, st, uuid.New(), uuid.New(), "Proposal", intakeTestPDF(t))
	if !errors.Is(err, dbErr) || !errors.Is(err, deleteErr) {
		t.Fatalf("joined error should retain DB and cleanup causes, got %v", err)
	}
}
