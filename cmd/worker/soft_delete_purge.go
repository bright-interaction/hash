// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

type purgeObjectDeleter interface {
	Delete(context.Context, string) error
}

type purgeRowDelete func(context.Context, *generated.Document) (int64, error)

// Soft-delete purge loop (carryover from audit fix #10).
//
// fix #10 changed DeleteDraftDocument from a hard DROP to flipping
// documents.deleted_at, plus added a PurgeSoftDeletedDocuments query
// that takes a cutoff timestamp. This loop is the cron that actually
// runs the purge so the grace window doesn't grow without bound.
//
// Cadence: every 6 hours. Cutoff: 90 days after deleted_at, matching
// the privacy-policy retention statement for in-flight DSR requests.
//
// Per-tick work is bounded and leased. A row is not hard-deleted until its
// document-owned source object is removed; storage failures leave the row (and
// therefore its cleanup key) available for a later retry.

const (
	softDeletePurgeInterval = 6 * time.Hour
	softDeleteGraceWindow   = 90 * 24 * time.Hour
	softDeletePurgeBatch    = 100
	softDeleteObjectTimeout = 15 * time.Second
)

func (w *worker) loopSoftDeletePurge(ctx context.Context) {
	tick := time.NewTicker(softDeletePurgeInterval)
	defer tick.Stop()
	w.runSoftDeletePurgeOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runSoftDeletePurgeOnce(ctx)
		}
	}
}

func (w *worker) runSoftDeletePurgeOnce(ctx context.Context) {
	cutoff := pgtype.Timestamptz{Time: time.Now().Add(-softDeleteGraceWindow), Valid: true}
	claimed, err := w.queries.ClaimSoftDeletedDocumentsForPurge(ctx, generated.ClaimSoftDeletedDocumentsForPurgeParams{
		Cutoff: cutoff, BatchLimit: softDeletePurgeBatch,
	})
	if err != nil {
		slog.Warn("soft_delete_purge: claim failed", "err", err, "cutoff", cutoff.Time)
		return
	}
	deleted := 0
	for _, doc := range claimed {
		if doc == nil {
			continue
		}
		rows, err := cleanupClaimedSoftDeletedDocument(ctx, doc, w.storage, func(ctx context.Context, claimed *generated.Document) (int64, error) {
			return w.queries.DeleteClaimedSoftDeletedDocument(ctx, generated.DeleteClaimedSoftDeletedDocumentParams{
				ID:        claimed.ID,
				OrgID:     claimed.OrgID,
				DeletedAt: cutoff,
				UpdatedAt: claimed.UpdatedAt,
			})
		})
		if err != nil {
			slog.Warn("soft_delete_purge: cleanup failed; retaining row for retry", "document_id", doc.ID, "err", err)
			continue
		}
		if rows > 0 {
			deleted++
		}
	}
	slog.Debug("soft_delete_purge: tick complete", "cutoff", cutoff.Time, "claimed", len(claimed), "deleted", deleted)
}

func cleanupClaimedSoftDeletedDocument(ctx context.Context, doc *generated.Document, objects purgeObjectDeleter, deleteRow purgeRowDelete) (int64, error) {
	if doc == nil || deleteRow == nil {
		return 0, errors.New("soft delete purge: document and row delete are required")
	}
	if key := purgeOwnedSourceKey(doc); key != "" {
		if objects == nil {
			return 0, errors.New("soft delete purge: storage unavailable")
		}
		deleteCtx, cancel := context.WithTimeout(ctx, softDeleteObjectTimeout)
		err := objects.Delete(deleteCtx, key)
		cancel()
		if err != nil {
			return 0, fmt.Errorf("delete source object: %w", err)
		}
	}
	return deleteRow(ctx, doc)
}

// purgeOwnedSourceKey mirrors the request-path cleanup predicate. Template
// clones share their source object and must retain it; final/audit aliases are
// legal evidence and must never be removed by draft retention cleanup.
func purgeOwnedSourceKey(doc *generated.Document) string {
	if doc == nil || doc.Status != "draft" || doc.TemplateID.Valid ||
		!doc.PdfStorageKey.Valid || doc.PdfStorageKey.String == "" {
		return ""
	}
	key := doc.PdfStorageKey.String
	if (doc.FinalPdfKey.Valid && doc.FinalPdfKey.String == key) ||
		(doc.AuditCertKey.Valid && doc.AuditCertKey.String == key) {
		return ""
	}
	return key
}
