// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package docintake holds the one-step "designed proposal -> signable
// pdf-source document" intake shared by the REST import handler and the MCP
// ingest tool, so both take exactly the same GDPR-safe clean + store + attest
// path before the (unchanged) field-designer + sign/stamp/seal flow runs.
package docintake

import (
	"context"
	"errors"
	"fmt"
	"path"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
)

// ErrSanitizePDF marks a failure to sanitize the input bytes as a PDF, so
// callers can map it to a 400 (bad upload) rather than a 500.
var ErrSanitizePDF = errors.New("docintake: pdf sanitize failed")

// ErrTooManyPages marks an intake whose page count exceeds maxIntakePages, so
// callers map it to a 400. Guards the HTML->PDF amplification vector (a tiny
// input can render into thousands of pages) whose direct-upload 50 MB cap the
// render path bypasses.
var ErrTooManyPages = errors.New("docintake: document exceeds the page limit")

// maxIntakePages bounds a one-step intake document. Legitimate proposals and
// contracts are far under this; the cap exists to reject amplification bombs
// before they reach the (in-memory, ctx-less) pdfcpu rewrite passes.
const maxIntakePages = 500

const orphanCleanupTimeout = 15 * time.Second

// documentQueries and objectStore keep the intake transaction boundary
// testable. The production *generated.Queries and *storage.Client implement
// these interfaces directly.
type documentQueries interface {
	CreatePDFDocument(context.Context, generated.CreatePDFDocumentParams) (*generated.Document, error)
	UpdateMetadataRedactionReport(context.Context, generated.UpdateMetadataRedactionReportParams) error
}

type objectStore interface {
	PutVersioned(context.Context, string, string, []byte) (storage.StoredObject, error)
	DeleteVersion(context.Context, string, string, []byte) error
}

// CreatePDFSourceDocument sanitizes the PDF bytes (strips /Info, XMP, JS,
// AcroForm, attachments, annotations), stores the cleaned copy, and creates a
// template-less pdf-source document ready for the field designer. Returns the
// document and its page count. The sign/stamp/seal path downstream is
// untouched, so the frozen audit-cert + hash-chain wire format is never
// affected by this intake.
func CreatePDFSourceDocument(ctx context.Context, q documentQueries, st objectStore, orgID, userID uuid.UUID, name string, data []byte) (*generated.Document, int, error) {
	cleaned, err := sanitize.Clean("proposal-pdf", "application/pdf", data)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrSanitizePDF, err)
	}
	// Reject an amplification bomb BEFORE storing it or handing it to the
	// downstream pdfcpu passes.
	pageCount, err := sanitize.PageCount(cleaned.Bytes)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: count sanitized PDF pages: %v", ErrSanitizePDF, err)
	}
	if pageCount > maxIntakePages {
		return nil, 0, fmt.Errorf("%w: %d pages exceeds the %d-page limit", ErrTooManyPages, pageCount, maxIntakePages)
	}
	key := path.Join("org", orgID.String(), "documents", uuid.NewString()+".pdf")
	stored, err := st.PutVersioned(ctx, key, "application/pdf", cleaned.Bytes)
	if err != nil {
		return nil, 0, err
	}
	d, err := q.CreatePDFDocument(ctx, generated.CreatePDFDocumentParams{
		OrgID:                       orgID,
		TemplateID:                  pgtype.UUID{}, // template-less one-shot intake
		Name:                        name,
		PdfStorageKey:               pgtype.Text{String: key, Valid: true},
		PdfSha256:                   stored.SHA256[:],
		PdfStorageVersionID:         pgtype.Text{String: stored.VersionID, Valid: true},
		EvidenceVersionPinsRequired: true,
		SenderID:                    userID,
		ExpiresAt:                   pgtype.Timestamptz{},
	})
	if err != nil {
		// Object storage and PostgreSQL cannot share a transaction. If the DB
		// insert fails after Put succeeded, compensate immediately using a
		// context detached from the request cancellation that commonly caused
		// the DB error. Otherwise every failed upload leaves an unreferenced PDF
		// in the bucket forever.
		cleanupErr := deleteAfterFailedWrite(ctx, st, key, stored)
		if cleanupErr != nil {
			return nil, 0, errors.Join(
				fmt.Errorf("create PDF document: %w", err),
				fmt.Errorf("delete orphaned PDF %q: %w", key, cleanupErr),
			)
		}
		return nil, 0, fmt.Errorf("create PDF document: %w", err)
	}
	// Attest the GDPR-safe cleaning on the document so the audit cert can
	// reference it without a template lookup.
	rep, rerr := sanitize.MergeReports(nil, cleaned.Report)
	if rerr != nil {
		cleanupErr := deleteAfterFailedWrite(ctx, st, key, stored)
		return nil, 0, errors.Join(fmt.Errorf("build metadata redaction report: %w", rerr), cleanupErr)
	}
	if err := q.UpdateMetadataRedactionReport(ctx, generated.UpdateMetadataRedactionReportParams{
		ID: d.ID, MetadataRedactionReport: rep,
	}); err != nil {
		cleanupErr := deleteAfterFailedWrite(ctx, st, key, stored)
		return nil, 0, errors.Join(fmt.Errorf("persist metadata redaction report: %w", err), cleanupErr)
	}
	return d, pageCount, nil
}

func deleteAfterFailedWrite(parent context.Context, st objectStore, key string, stored storage.StoredObject) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), orphanCleanupTimeout)
	defer cancel()
	return st.DeleteVersion(cleanupCtx, key, stored.VersionID, stored.SHA256[:])
}

// Compile-time assertions keep interface drift visible at the storage/query
// boundary rather than surfacing only in a handler build.
var _ objectStore = (*storage.Client)(nil)
var _ documentQueries = (*generated.Queries)(nil)
