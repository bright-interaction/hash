// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package versions implements document snapshotting, history, diffing, and
// restore for Hash. It is the foundation Phase 8.1 ships first because
// negotiation copilot (#3), court-ready evidence (#10), and the timeline UI
// (#8.8) all depend on a single canonical version primitive.
//
// A version is an immutable snapshot of a document's block tree, variables,
// name, and source kind, taken at the moment a state-changing edit completes.
// Versions form a parent chain via parent_id, which allows linear history,
// restore semantics, and future branching for negotiation drafts without
// schema changes.
package versions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/db/generated"
)

// Via labels the origin of a version. Stored in document_versions.created_via
// and surfaced in the timeline UI so reviewers can filter agent vs human edits.
type Via string

const (
	ViaHuman   Via = "human"
	ViaMCP     Via = "mcp"
	ViaCRMBind Via = "crm-bind"
	ViaAgent   Via = "agent"
	ViaRestore Via = "restore"
	ViaImport  Via = "import"
)

func (v Via) Valid() bool {
	switch v {
	case ViaHuman, ViaMCP, ViaCRMBind, ViaAgent, ViaRestore, ViaImport:
		return true
	}
	return false
}

// Engine snapshots, lists, fetches, and restores document versions.
type Engine struct {
	Q *generated.Queries
}

// New builds an Engine bound to a sqlc Queries handle.
func New(q *generated.Queries) *Engine {
	return &Engine{Q: q}
}

// SnapshotInput carries the fields a caller has when persisting a new version.
// Document fields (name, source kind, variables, blocks) are copied from the
// caller's view of the document, not re-read inside Snapshot. This avoids a
// race where another writer flips the document between the edit and the
// snapshot. Callers in handler/sign code already hold the relevant rows.
type SnapshotInput struct {
	DocumentID  uuid.UUID
	OrgID       uuid.UUID
	Name        string
	SourceKind  string
	BlocksJSON  json.RawMessage // may be nil for source_kind='pdf'
	VariablesJS json.RawMessage // may be nil; treated as '{}'
	CreatedBy   *uuid.UUID      // null means system-attributed (e.g., import via API key)
	Via         Via
	Summary     string // optional one-line description shown in the timeline
}

// Snapshot persists a new version. Returns the inserted row.
func (e *Engine) Snapshot(ctx context.Context, in SnapshotInput) (*generated.DocumentVersion, error) {
	if in.DocumentID == uuid.Nil {
		return nil, errors.New("snapshot: document_id required")
	}
	if in.OrgID == uuid.Nil {
		return nil, errors.New("snapshot: org_id required")
	}
	if in.Name == "" {
		return nil, errors.New("snapshot: name required")
	}
	if in.SourceKind != "blocks" && in.SourceKind != "pdf" {
		return nil, fmt.Errorf("snapshot: invalid source_kind %q", in.SourceKind)
	}
	if in.Via == "" {
		in.Via = ViaHuman
	}
	if !in.Via.Valid() {
		return nil, fmt.Errorf("snapshot: invalid via %q", in.Via)
	}
	if len(in.VariablesJS) == 0 {
		in.VariablesJS = json.RawMessage(`{}`)
	}
	maxNo, err := e.Q.GetLatestDocumentVersionNo(ctx, in.DocumentID)
	if err != nil {
		return nil, fmt.Errorf("snapshot: latest version_no: %w", err)
	}
	var parentID pgtype.UUID
	if maxNo > 0 {
		latest, err := e.Q.GetLatestDocumentVersion(ctx, in.DocumentID)
		if err != nil {
			return nil, fmt.Errorf("snapshot: get latest: %w", err)
		}
		parentID = pgtype.UUID{Bytes: latest.ID, Valid: true}
	}
	var createdBy pgtype.UUID
	if in.CreatedBy != nil {
		createdBy = pgtype.UUID{Bytes: *in.CreatedBy, Valid: true}
	}
	row, err := e.Q.InsertDocumentVersion(ctx, generated.InsertDocumentVersionParams{
		DocumentID:    in.DocumentID,
		OrgID:         in.OrgID,
		VersionNo:     maxNo + 1,
		BlockTreeJson: in.BlocksJSON,
		VariablesJson: in.VariablesJS,
		Name:          in.Name,
		SourceKind:    in.SourceKind,
		Summary:       in.Summary,
		CreatedBy:     createdBy,
		CreatedVia:    string(in.Via),
		ParentID:      parentID,
		SchemaVersion: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("snapshot: insert: %w", err)
	}
	return row, nil
}

// History returns up to limit most-recent versions in DESC version_no order.
func (e *Engine) History(ctx context.Context, docID uuid.UUID, limit int32) ([]*generated.DocumentVersion, error) {
	if limit <= 0 {
		limit = 50
	}
	return e.Q.ListDocumentVersions(ctx, generated.ListDocumentVersionsParams{
		DocumentID: docID,
		Limit:      limit,
	})
}

// Get fetches a single version by ID.
func (e *Engine) Get(ctx context.Context, id uuid.UUID) (*generated.DocumentVersion, error) {
	return e.Q.GetDocumentVersion(ctx, id)
}

// GetByNo fetches a version by document + version_no, the form callers use.
func (e *Engine) GetByNo(ctx context.Context, docID uuid.UUID, versionNo int32) (*generated.DocumentVersion, error) {
	return e.Q.GetDocumentVersionByNo(ctx, generated.GetDocumentVersionByNoParams{
		DocumentID: docID,
		VersionNo:  versionNo,
	})
}

// Latest returns the highest-numbered version for a document.
func (e *Engine) Latest(ctx context.Context, docID uuid.UUID) (*generated.DocumentVersion, error) {
	return e.Q.GetLatestDocumentVersion(ctx, docID)
}

// Count returns the number of stored versions for a document.
func (e *Engine) Count(ctx context.Context, docID uuid.UUID) (int32, error) {
	return e.Q.CountDocumentVersions(ctx, docID)
}

// RestoreInput targets a specific historical version to materialize back onto
// the live documents row. The handler layer is responsible for the actual
// documents UPDATE because that's where state-machine guards (cannot restore
// onto a completed/voided doc) live; Restore here only validates and snapshots
// the restore action so the audit trail captures it.
type RestoreInput struct {
	DocumentID    uuid.UUID
	TargetVersion int32
	OrgID         uuid.UUID
	CreatedBy     *uuid.UUID
}

// Restore validates that the target version exists and belongs to the
// document, then snapshots a new version (Via='restore') carrying the
// historical content. The caller persists the returned blocks/variables
// onto the documents row in the same transaction.
func (e *Engine) Restore(ctx context.Context, in RestoreInput) (target, snapshot *generated.DocumentVersion, err error) {
	if in.DocumentID == uuid.Nil {
		return nil, nil, errors.New("restore: document_id required")
	}
	if in.TargetVersion <= 0 {
		return nil, nil, errors.New("restore: target_version must be >= 1")
	}
	target, err = e.GetByNo(ctx, in.DocumentID, in.TargetVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("restore: target lookup: %w", err)
	}
	if target.OrgID != in.OrgID {
		return nil, nil, errors.New("restore: target version belongs to a different org")
	}
	snap, err := e.Snapshot(ctx, SnapshotInput{
		DocumentID:  in.DocumentID,
		OrgID:       in.OrgID,
		Name:        target.Name,
		SourceKind:  target.SourceKind,
		BlocksJSON:  target.BlockTreeJson,
		VariablesJS: target.VariablesJson,
		CreatedBy:   in.CreatedBy,
		Via:         ViaRestore,
		Summary:     fmt.Sprintf("restored from v%d", target.VersionNo),
	})
	if err != nil {
		return nil, nil, err
	}
	return target, snap, nil
}

// PgUUIDFrom converts a *uuid.UUID into the pgtype.UUID form sqlc-generated
// callers expect. Exported so handler glue doesn't need to import pgtype just
// to round-trip an optional UUID.
func PgUUIDFrom(u *uuid.UUID) pgtype.UUID {
	if u == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *u, Valid: true}
}
