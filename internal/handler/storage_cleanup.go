// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
)

const objectCleanupTimeout = 15 * time.Second

type objectDeleter interface {
	DeleteVersion(context.Context, string, string, []byte) error
}

type cleanupObjectVersion struct {
	Key       string
	VersionID string
	SHA256    []byte
}

// deleteObjectDetached performs compensating object-store cleanup even when
// the HTTP request was canceled or timed out. Reusing the request context here
// is a common orphan leak: the cleanup call fails immediately for exactly the
// requests most likely to have failed mid-write.
func deleteObjectDetached(parent context.Context, st objectDeleter, object cleanupObjectVersion) error {
	if st == nil || object.Key == "" || object.VersionID == "" || len(object.SHA256) != sha256.Size {
		return errors.New("exact object cleanup identity is incomplete")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), objectCleanupTimeout)
	defer cancel()
	return st.DeleteVersion(ctx, object.Key, object.VersionID, object.SHA256)
}

// draftSourceObjectVersions returns only document-owned transient source
// versions. A cleanup candidate without the complete persisted
// key/SHA-256/VersionId commitment is refused: resolving "latest" or scanning
// legacy history at deletion time could erase a shared or attacker-shadowed
// version.
// A PDF cloned from a template shares the template's object with every clone,
// so its key must never be deleted with one document. Final PDFs and audit
// certificates are legally retained evidence and are deliberately excluded.
func draftSourceObjectVersions(doc *generated.Document) ([]cleanupObjectVersion, error) {
	if doc == nil || doc.Status != "draft" || doc.TemplateID.Valid ||
		!doc.PdfStorageKey.Valid || doc.PdfStorageKey.String == "" {
		return nil, nil
	}
	key := doc.PdfStorageKey.String
	if (doc.FinalPdfKey.Valid && doc.FinalPdfKey.String == key) ||
		(doc.AuditCertKey.Valid && doc.AuditCertKey.String == key) {
		return nil, nil
	}
	if !doc.EvidenceVersionPinsRequired || !doc.PdfStorageVersionID.Valid ||
		strings.TrimSpace(doc.PdfStorageVersionID.String) == "" || len(doc.PdfSha256) != sha256.Size {
		return nil, errors.New("draft source object lacks its required exact-version cleanup commitment")
	}
	return []cleanupObjectVersion{{
		Key: key, VersionID: doc.PdfStorageVersionID.String, SHA256: append([]byte(nil), doc.PdfSha256...),
	}}, nil
}

func requiredDraftSourceObjectVersion(doc *generated.Document) (cleanupObjectVersion, error) {
	objects, err := draftSourceObjectVersions(doc)
	if err != nil {
		return cleanupObjectVersion{}, err
	}
	if len(objects) != 1 {
		return cleanupObjectVersion{}, errors.New("document does not own exactly one draft source object version")
	}
	return objects[0], nil
}
