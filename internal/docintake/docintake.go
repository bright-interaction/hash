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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/sanitize"
	"github.com/brightinteraction/hash/internal/storage"
)

// ErrSanitizePDF marks a failure to sanitize the input bytes as a PDF, so
// callers can map it to a 400 (bad upload) rather than a 500.
var ErrSanitizePDF = errors.New("docintake: pdf sanitize failed")

// CreatePDFSourceDocument sanitizes the PDF bytes (strips /Info, XMP, JS,
// AcroForm, attachments, annotations), stores the cleaned copy, and creates a
// template-less pdf-source document ready for the field designer. Returns the
// document and its page count. The sign/stamp/seal path downstream is
// untouched, so the frozen audit-cert + hash-chain wire format is never
// affected by this intake.
func CreatePDFSourceDocument(ctx context.Context, q *generated.Queries, st *storage.Client, orgID, userID uuid.UUID, name string, data []byte) (*generated.Document, int, error) {
	cleaned, err := sanitize.Clean("proposal-pdf", "application/pdf", data)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrSanitizePDF, err)
	}
	key := path.Join("org", orgID.String(), "documents", uuid.NewString()+".pdf")
	sha, err := st.Put(ctx, key, "application/pdf", cleaned.Bytes)
	if err != nil {
		return nil, 0, err
	}
	pageCount, _ := sanitize.PageCount(cleaned.Bytes)
	d, err := q.CreatePDFDocument(ctx, generated.CreatePDFDocumentParams{
		OrgID:         orgID,
		TemplateID:    pgtype.UUID{}, // template-less one-shot intake
		Name:          name,
		PdfStorageKey: pgtype.Text{String: key, Valid: true},
		PdfSha256:     sha[:],
		SenderID:      userID,
		ExpiresAt:     pgtype.Timestamptz{},
	})
	if err != nil {
		return nil, 0, err
	}
	// Attest the GDPR-safe cleaning on the document so the audit cert can
	// reference it without a template lookup.
	if rep, rerr := sanitize.MergeReports(nil, cleaned.Report); rerr == nil {
		_ = q.UpdateMetadataRedactionReport(ctx, generated.UpdateMetadataRedactionReportParams{
			ID:                      d.ID,
			MetadataRedactionReport: rep,
		})
	}
	return d, pageCount, nil
}
