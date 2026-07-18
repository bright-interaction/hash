// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/versions"
)

// registerVersionTools mounts the Phase 8.1 history surface for agents.
// list_document_versions, diff_document_versions, and restore_document_version
// give agents the same insight into change history that the timeline UI gives
// humans, which is the substrate the negotiation copilot (Phase 11.2) will
// drive into in Phase 11.
func registerVersionTools(s *Server, d Deps) {
	if d.Versions == nil {
		// Versions engine is optional during early bring-up; emit no tools
		// rather than error here so a stack without the migration applied
		// still serves the rest of the API.
		return
	}

	s.RegisterTool(ToolDef{
		Name:        "list_document_versions",
		Description: "List the document's version history newest-first. Each version captures the full block tree, variables, and authorship metadata at the moment of the edit.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"limit":       intSchema("max versions to return (default 50, max 200)", 1, 200, 50),
		}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
				Limit      int    `json:"limit"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			if _, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID}); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("document not found")
				}
				return nil, err
			}
			limit := p.Limit
			if limit <= 0 {
				limit = 50
			}
			if limit > 200 {
				limit = 200
			}
			rows, err := d.Versions.History(r.Context(), id, int32(limit))
			if err != nil {
				return nil, err
			}
			out := make([]map[string]any, 0, len(rows))
			for _, v := range rows {
				out = append(out, versionToMap(v))
			}
			return map[string]any{"versions": out, "count": len(out)}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "diff_document_versions",
		Description: "Block-level diff between two versions. 'to' defaults to the latest, 'from' to to-1. Returns Added/Removed/Modified/Moved entries keyed by stable block_id, plus aggregate counts.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"from":        intSchema("source version_no (defaults to to-1)", 1, 100000, 0),
			"to":          intSchema("target version_no (defaults to latest)", 1, 100000, 0),
		}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
				From       int    `json:"from"`
				To         int    `json:"to"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			if _, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID}); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("document not found")
				}
				return nil, err
			}
			maxNo, err := d.Queries.GetLatestDocumentVersionNo(r.Context(), id)
			if err != nil {
				return nil, err
			}
			if maxNo <= 0 {
				return map[string]any{
					"from": nil, "to": nil, "changes": []any{}, "counts": versions.DiffCounts{},
				}, nil
			}
			to := int32(p.To)
			if to <= 0 {
				to = maxNo
			}
			from := int32(p.From)
			if from <= 0 {
				from = to - 1
			}
			if from < 1 {
				from = 1
			}
			if from > to {
				return nil, errors.New("from must be <= to")
			}
			if from == to {
				v, err := d.Versions.GetByNo(r.Context(), id, to)
				if err != nil {
					return nil, err
				}
				if v.OrgID != u.OrgID {
					return nil, errors.New("version not found")
				}
				return map[string]any{
					"from":    versionSide(v),
					"to":      versionSide(v),
					"changes": []any{},
					"counts":  versions.DiffCounts{},
				}, nil
			}
			fromV, err := d.Versions.GetByNo(r.Context(), id, from)
			if err != nil {
				return nil, fmt.Errorf("from v%d: %w", from, err)
			}
			toV, err := d.Versions.GetByNo(r.Context(), id, to)
			if err != nil {
				return nil, fmt.Errorf("to v%d: %w", to, err)
			}
			if fromV.OrgID != u.OrgID || toV.OrgID != u.OrgID {
				return nil, errors.New("version not found")
			}
			changes, err := versions.Diff(fromV.BlockTreeJson, toV.BlockTreeJson)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"from":    versionSide(fromV),
				"to":      versionSide(toV),
				"changes": changes,
				"counts":  versions.SummarizeCounts(changes),
			}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "restore_document_version",
		Write:       true,
		Description: "Materialize a historical version onto the live draft document. Logs a 'restore' event and snapshots a new version capturing the action. Refuses on non-draft documents.",
		InputSchema: schemaObject(map[string]any{
			"document_id":    stringSchema("document uuid (must be in draft state, source_kind=blocks)"),
			"target_version": intSchema("version_no to restore (must already exist)", 1, 100000, 0),
		}, []string{"document_id", "target_version"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID    string `json:"document_id"`
				TargetVersion int    `json:"target_version"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			if p.TargetVersion <= 0 {
				return nil, errors.New("target_version must be >= 1")
			}
			doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			if doc.Status != "draft" {
				return nil, fmt.Errorf("document not editable (status=%s)", doc.Status)
			}
			if doc.SourceKind != "blocks" {
				return nil, errors.New("restore only supported on block-source documents")
			}
			target, _, err := d.Versions.Restore(r.Context(), versions.RestoreInput{
				DocumentID:    id,
				TargetVersion: int32(p.TargetVersion),
				OrgID:         u.OrgID,
				CreatedBy:     &u.UserID,
			})
			if err != nil {
				return nil, err
			}
			if target.SourceKind != "blocks" {
				return nil, errors.New("target version is not block-source")
			}
			updated, err := d.Queries.UpdateDocumentBlocks(r.Context(), generated.UpdateDocumentBlocksParams{
				ID:            id,
				OrgID:         u.OrgID,
				BlocksJson:    target.BlockTreeJson,
				VariablesJson: target.VariablesJson,
			})
			if err != nil {
				return nil, err
			}
			_, _ = d.Audit.Log(r.Context(), audit.Entry{
				OrgID:       u.OrgID,
				ActorUserID: &u.UserID,
				DocumentID:  &id,
				Kind:        audit.KindDocumentUpdated,
				Payload: map[string]any{
					"via":             "mcp",
					"tool":            "restore_document_version",
					"restored_from_v": target.VersionNo,
				},
			})
			return map[string]any{
				"document_id":     updated.ID.String(),
				"name":            updated.Name,
				"status":          updated.Status,
				"restored_from_v": target.VersionNo,
			}, nil
		},
	})
}

// versionToMap shapes a generated.DocumentVersion for the MCP wire. Block tree
// and variables JSON are returned as-is so agents can pass them straight back
// to set_document_blocks for restore-without-restore patterns.
func versionToMap(v *generated.DocumentVersion) map[string]any {
	out := map[string]any{
		"id":             v.ID.String(),
		"document_id":    v.DocumentID.String(),
		"version_no":     v.VersionNo,
		"name":           v.Name,
		"source_kind":    v.SourceKind,
		"summary":        v.Summary,
		"created_via":    v.CreatedVia,
		"created_at":     v.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		"schema_version": v.SchemaVersion,
		"blocks_json":    json.RawMessage(v.BlockTreeJson),
		"variables_json": json.RawMessage(v.VariablesJson),
	}
	if v.CreatedBy.Valid {
		out["created_by"] = uuid.UUID(v.CreatedBy.Bytes).String()
	}
	if v.ParentID.Valid {
		out["parent_id"] = uuid.UUID(v.ParentID.Bytes).String()
	}
	return out
}

func versionSide(v *generated.DocumentVersion) versions.DiffSide {
	count, _ := mcpBlockCount(v.BlockTreeJson)
	return versions.DiffSide{
		VersionID:  v.ID.String(),
		VersionNo:  v.VersionNo,
		DocumentID: v.DocumentID.String(),
		BlockCount: count,
		NameAtRev:  v.Name,
	}
}

func mcpBlockCount(raw json.RawMessage) (int, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	var t struct {
		Blocks []json.RawMessage `json:"blocks"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return 0, err
	}
	return len(t.Blocks), nil
}
