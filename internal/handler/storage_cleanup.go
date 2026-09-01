// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
)

const objectCleanupTimeout = 15 * time.Second

type objectDeleter interface {
	Delete(context.Context, string) error
}

// deleteObjectDetached performs compensating object-store cleanup even when
// the HTTP request was canceled or timed out. Reusing the request context here
// is a common orphan leak: the cleanup call fails immediately for exactly the
// requests most likely to have failed mid-write.
func deleteObjectDetached(parent context.Context, st objectDeleter, key string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), objectCleanupTimeout)
	defer cancel()
	return st.Delete(ctx, key)
}

// draftSourceObjectKeys returns only document-owned transient source objects.
// A PDF cloned from a template shares the template's object with every clone,
// so its key must never be deleted with one document. Final PDFs and audit
// certificates are legally retained evidence and are deliberately excluded.
func draftSourceObjectKeys(doc *generated.Document) []string {
	if doc == nil || doc.Status != "draft" || doc.TemplateID.Valid ||
		!doc.PdfStorageKey.Valid || doc.PdfStorageKey.String == "" {
		return nil
	}
	key := doc.PdfStorageKey.String
	if (doc.FinalPdfKey.Valid && doc.FinalPdfKey.String == key) ||
		(doc.AuditCertKey.Valid && doc.AuditCertKey.String == key) {
		return nil
	}
	return []string{key}
}
