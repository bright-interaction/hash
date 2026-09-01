// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"errors"
	"math/big"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// registerFieldTools exposes the v1.2 fillable-field surface over MCP.
// Senders (or agents) can add text/date/checkbox/dropdown/initial fields
// to a document so a recipient can fill structured values before the
// signature step. Signature-type fields are intentionally NOT exposed
// here ,  the sign engine manages those.
func registerFieldTools(s *Server, d Deps) {
	s.RegisterTool(ToolDef{
		Name:  "add_document_field",
		Write: true,
		Description: "Add a field overlay to a document. Type is one of text|date|checkbox|dropdown|initial, or 'signature' on a pdf-source document (signature requires recipient_id). " +
			"Coordinates are 0..100 percent of the rendered page. recipient_id is optional for fillable fields; nil = any recipient may fill.",
		InputSchema: schemaObject(map[string]any{
			"document_id":  stringSchema("document uuid"),
			"recipient_id": stringSchema("optional recipient uuid; empty = any signer"),
			"type":         stringSchema("text|date|checkbox|dropdown|initial"),
			"page":         intSchema("1-indexed PDF page", 1, 1000, 1),
			"x_pct":        intSchema("left edge as 0..10000 (basis points of page width)", 0, 10000, 0),
			"y_pct":        intSchema("top edge as 0..10000", 0, 10000, 0),
			"w_pct":        intSchema("width as 0..10000", 0, 10000, 1500),
			"h_pct":        intSchema("height as 0..10000", 0, 10000, 400),
			"required":     stringSchema("'true' or 'false' (default true)"),
			"label":        stringSchema("display label shown above the input"),
		}, []string{"document_id", "type"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID  string `json:"document_id"`
				RecipientID string `json:"recipient_id"`
				Type        string `json:"type"`
				Page        int    `json:"page"`
				XPct        int    `json:"x_pct"`
				YPct        int    `json:"y_pct"`
				WPct        int    `json:"w_pct"`
				HPct        int    `json:"h_pct"`
				Required    string `json:"required"`
				Label       string `json:"label"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			docID, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), docID); err != nil {
				return nil, err
			}
			doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID})
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("document not found")
				}
				return nil, err
			}
			if doc.Status != "draft" {
				return nil, errors.New("document not in draft state")
			}
			switch p.Type {
			case "text", "date", "checkbox", "dropdown", "initial":
			case "signature":
				// PDF-source docs place signature fields visually (no block tree
				// to carry them), mirroring the REST handleAddField so an agent
				// can drop "sign here" boxes on an imported proposal.
				if doc.SourceKind != "pdf" {
					return nil, errors.New("signature fields come from the block tree for block-source documents")
				}
				if p.RecipientID == "" {
					return nil, errors.New("signature fields must be assigned to a recipient")
				}
			default:
				return nil, errors.New("type must be text|date|checkbox|dropdown|initial|signature")
			}
			recipientID := pgtype.UUID{}
			if p.RecipientID != "" {
				rid, err := uuid.Parse(p.RecipientID)
				if err != nil {
					return nil, errors.New("recipient_id must be a uuid")
				}
				recipientID = pgtype.UUID{Bytes: rid, Valid: true}
			}
			required := p.Required != "false"
			page := p.Page
			if page < 1 {
				page = 1
			}
			row, err := audit.CommitMutation(r.Context(), d.Pool, d.Audit,
				func(q *generated.Queries) (*generated.DocumentField, error) {
					return q.CreateDraftField(r.Context(), generated.CreateDraftFieldParams{
						DocumentID:  docID,
						RecipientID: recipientID,
						Type:        p.Type,
						Page:        int32(page),
						XPct:        bpToNumeric(p.XPct),
						YPct:        bpToNumeric(p.YPct),
						WPct:        bpToNumeric(p.WPct),
						HPct:        bpToNumeric(p.HPct),
						Required:    required,
						Label:       pgtype.Text{String: p.Label, Valid: p.Label != ""},
						OptionsJson: []byte(`{}`),
					})
				},
				func(row *generated.DocumentField) audit.Entry {
					return audit.Entry{
						OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &docID,
						Kind: "document.field_added",
						Payload: map[string]any{
							"field_id": row.ID.String(),
							"type":     p.Type,
							"via":      "mcp",
						},
					}
				},
			)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not in draft state or recipient does not belong to document")
			}
			if err != nil {
				return nil, err
			}
			return fieldRowToMCP(row), nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "list_document_fields",
		Description: "List the fillable fields attached to a document (both signature and non-signature). Use this before sending to confirm every recipient has the required fields assigned.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
		}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			docID, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), docID); err != nil {
				return nil, err
			}
			if _, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID}); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("document not found")
				}
				return nil, err
			}
			rows, err := d.Queries.ListFieldsByDocument(r.Context(), docID)
			if err != nil {
				return nil, err
			}
			out := make([]map[string]any, 0, len(rows))
			for _, f := range rows {
				out = append(out, fieldRowToMCP(f))
			}
			return map[string]any{"fields": out, "count": len(out)}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "delete_document_field",
		Write:       true,
		Description: "Remove a fillable field from a document. Does NOT affect signatures already captured.",
		InputSchema: schemaObject(map[string]any{
			"field_id": stringSchema("uuid of the field to delete"),
		}, []string{"field_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				FieldID string `json:"field_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.FieldID)
			if err != nil {
				return nil, errors.New("field_id must be a uuid")
			}
			// Confine a doc-scoped agent token: resolve the field's owning doc
			// (org-scoped) and enforce scope before deleting.
			ownerDoc, err := d.Queries.GetFieldOwnerDoc(r.Context(), generated.GetFieldOwnerDocParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("field not found")
			}
			if err != nil {
				return nil, err
			}
			if err := auth.EnforceDocScope(r.Context(), ownerDoc); err != nil {
				return nil, err
			}
			doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: ownerDoc, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			if doc.Status != "draft" {
				return nil, errors.New("document not in draft state")
			}
			if _, err := d.Queries.DeleteFieldByID(r.Context(), generated.DeleteFieldByIDParams{
				ID: id, OrgID: u.OrgID,
			}); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("document not in draft state")
				}
				return nil, err
			}
			return map[string]any{"deleted": id.String()}, nil
		},
	})
}

// bpToNumeric converts a 0..10000 basis-point coordinate to a
// pgtype.Numeric stored as fixed 4-decimal. Mirrors handler.pctToNumeric
// but the MCP wire shape takes integers so JSON-RPC clients don't lose
// precision crossing float boundaries.
func bpToNumeric(bp int) pgtype.Numeric {
	return pgtype.Numeric{Int: big.NewInt(int64(bp)), Exp: -4, Valid: true}
}

func fieldRowToMCP(f *generated.DocumentField) map[string]any {
	out := map[string]any{
		"id":          f.ID.String(),
		"document_id": f.DocumentID.String(),
		"type":        f.Type,
		"page":        f.Page,
		"required":    f.Required,
	}
	if f.RecipientID.Valid {
		out["recipient_id"] = uuid.UUID(f.RecipientID.Bytes).String()
	}
	if f.Label.Valid {
		out["label"] = f.Label.String
	}
	if f.Value.Valid {
		out["value"] = f.Value.String
	}
	if f.CompletedAt.Valid {
		out["completed_at"] = f.CompletedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return out
}
