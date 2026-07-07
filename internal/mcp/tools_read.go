package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/db/generated"
)

// registerReadTools mounts the safe, read-only tools. These are the same
// shape Phase 1 of brightcrm/dockyard/atomicsite shipped: list_*, get_*,
// search_*, plus an org-scoped capabilities reader.
func registerReadTools(s *Server, d Deps) {
	s.RegisterTool(ToolDef{
		Name:        "list_templates",
		Description: "List the org's active (non-archived) templates, newest first.",
		InputSchema: schemaObject(map[string]any{
			"limit":  intSchema("max rows", 1, 200, 50),
			"offset": intSchema("offset", 0, 100000, 0),
		}, nil),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				Limit  int `json:"limit"`
				Offset int `json:"offset"`
			}
			_ = MustParseArgs(args, &p)
			limit := int32(50)
			if p.Limit > 0 && p.Limit <= 200 {
				limit = int32(p.Limit)
			}
			offset := int32(p.Offset)
			rows, err := d.Queries.ListTemplates(r.Context(), generated.ListTemplatesParams{
				OrgID: u.OrgID, Limit: limit, Offset: offset,
			})
			if err != nil {
				return nil, fmt.Errorf("list templates: %w", err)
			}
			return map[string]any{"templates": rows, "count": len(rows)}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "get_template",
		Description: "Fetch a single template by id (org-scoped).",
		InputSchema: schemaObject(map[string]any{
			"id": stringSchema("template id (uuid)"),
		}, []string{"id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				ID string `json:"id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.ID)
			if err != nil {
				return nil, errors.New("id must be a uuid")
			}
			t, err := d.Queries.GetTemplate(r.Context(), generated.GetTemplateParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("template not found")
			}
			if err != nil {
				return nil, err
			}
			return t, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "list_documents",
		Description: "List documents in the caller's org. Optional status filter restricts to one or more states.",
		InputSchema: schemaObject(map[string]any{
			"status": map[string]any{
				"type":        "array",
				"description": "Optional status filter; values: draft, sent, in_progress, completed, declined, voided, expired",
				"items":       map[string]any{"type": "string"},
			},
			"limit":  intSchema("max rows", 1, 200, 50),
			"offset": intSchema("offset", 0, 100000, 0),
		}, nil),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				Status []string `json:"status"`
				Limit  int      `json:"limit"`
				Offset int      `json:"offset"`
			}
			_ = MustParseArgs(args, &p)
			// v1.1: per-doc tokens see exactly one document via this
			// listing surface; return the bound doc alone.
			if scope, ok := auth.DocumentScopeFromContext(r.Context()); ok {
				doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: scope, OrgID: u.OrgID})
				if err != nil {
					return map[string]any{"documents": []any{}, "count": 0}, nil
				}
				return map[string]any{"documents": []*generated.Document{doc}, "count": 1}, nil
			}
			limit := int32(50)
			if p.Limit > 0 && p.Limit <= 200 {
				limit = int32(p.Limit)
			}
			rows, err := d.Queries.ListDocuments(r.Context(), generated.ListDocumentsParams{
				OrgID: u.OrgID, Column2: p.Status, Limit: limit, Offset: int32(p.Offset),
			})
			if err != nil {
				return nil, err
			}
			return map[string]any{"documents": rows, "count": len(rows)}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "get_document",
		Description: "Fetch a single document by id, including blocks_json and metadata.",
		InputSchema: schemaObject(map[string]any{
			"id": stringSchema("document id (uuid)"),
		}, []string{"id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				ID string `json:"id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.ID)
			if err != nil {
				return nil, errors.New("id must be a uuid")
			}
			// v1.1: per-doc agent tokens are scoped to a single
			// document; reject reads of any other doc.
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			return doc, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "search_documents",
		Description: "Find documents by case-insensitive substring match on name. Returns up to 50 results.",
		InputSchema: schemaObject(map[string]any{
			"query": stringSchema("substring to match against document name"),
		}, []string{"query"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				Query string `json:"query"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			// A document-scoped token must not enumerate the org. Constrain the
			// result to the single scoped document, and only if it matches.
			if scope, ok := auth.DocumentScopeFromContext(r.Context()); ok {
				doc, derr := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: scope, OrgID: u.OrgID})
				if derr != nil || !strings.Contains(strings.ToLower(doc.Name), strings.ToLower(p.Query)) {
					return map[string]any{"documents": []*generated.Document{}, "count": 0}, nil
				}
				return map[string]any{"documents": []*generated.Document{doc}, "count": 1}, nil
			}
			rows, err := d.Queries.SearchDocumentsByName(r.Context(), generated.SearchDocumentsByNameParams{
				OrgID:   u.OrgID,
				Column2: pgtype.Text{String: p.Query, Valid: true},
				Limit:   50,
			})
			if err != nil {
				return nil, err
			}
			return map[string]any{"documents": rows, "count": len(rows)}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "list_recipients",
		Description: "List the recipients of a document.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document id (uuid)"),
		}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			// A document-scoped token may only read its own document.
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			// Cross-tenant check.
			if _, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID}); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("document not found")
				}
				return nil, err
			}
			rows, err := d.Queries.ListRecipientsByDocument(r.Context(), id)
			if err != nil {
				return nil, err
			}
			return map[string]any{"recipients": rows}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "get_document_events",
		Description: "Return up to 200 most recent events for a document (audit trail).",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document id (uuid)"),
		}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			// A document-scoped token may only read its own document's events.
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			if _, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID}); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("document not found")
				}
				return nil, err
			}
			rows, err := d.Queries.ListEventsByDocument(r.Context(), generated.ListEventsByDocumentParams{
				DocumentID: pgtypeUUID(id),
				Limit:      200,
			})
			if err != nil {
				return nil, err
			}
			return map[string]any{"events": rows}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "get_org_metrics",
		Description: "Return aggregate metrics for the caller's org: total documents, by-status breakdown, total templates.",
		InputSchema: schemaObject(map[string]any{}, nil),
		Handler: func(r *http.Request, _ json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			tplCount, _ := d.Queries.CountTemplates(r.Context(), u.OrgID)
			docCount, _ := d.Queries.CountDocuments(r.Context(), generated.CountDocumentsParams{OrgID: u.OrgID})
			return map[string]any{
				"templates_active": tplCount,
				"documents_total":  docCount,
			}, nil
		},
	})
}

// schemaObject helps build a JSON schema fragment without writing the same
// wrapping over and over. Pass a map of property-name → schema, and an
// optional `required` list.
func schemaObject(props map[string]any, required []string) map[string]any {
	out := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

func stringSchema(description string) map[string]any {
	return map[string]any{"type": "string", "description": description}
}

func intSchema(description string, min, max, def int) map[string]any {
	return map[string]any{
		"type":        "integer",
		"description": description,
		"minimum":     min,
		"maximum":     max,
		"default":     def,
	}
}
