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
	"github.com/brightinteraction/hash/internal/resolver"
)

// registerVariableBindingTools mounts the Phase 8.2 variable resolver
// surface for agents. Agents can:
//   - bind a {{var}} placeholder to a live BrightCRM deal/contact, an SVAR
//     scanner finding, or an org setting (one tool per source kind so the
//     schemas stay precise);
//   - list all bindings for a doc;
//   - delete a binding;
//   - preview the fully-resolved variable map (incl. which source answered).
//
// Once a doc transitions to non-draft, bindings are read-only and renders
// pull from the frozen variables_json the send-handler wrote at freeze time.
func registerVariableBindingTools(s *Server, d Deps) {
	if d.Resolver == nil {
		return
	}

	s.RegisterTool(ToolDef{
		Name:        "list_variable_bindings",
		Description: "Return every variable binding on a document, including last_value + last_resolved + last_error. Helpful for an agent to see what's live before deciding what to overwrite.",
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
			rows, err := d.Queries.ListVariableBindings(r.Context(), id)
			if err != nil {
				return nil, err
			}
			out := make([]map[string]any, 0, len(rows))
			for _, b := range rows {
				out = append(out, bindingRow(b))
			}
			return map[string]any{"bindings": out, "count": len(out)}, nil
		},
	})

	bindHandler := func(name string, kind resolver.SourceKind, refField, pathField string) ToolDef {
		return ToolDef{
			Name: name,
			Description: fmt.Sprintf(
				"Bind a {{variable}} to a %s source. The value resolves live at render time on draft docs; on send, the resolved value is frozen into the document version snapshot.",
				kind),
			InputSchema: schemaObject(map[string]any{
				"document_id": stringSchema("document uuid (must be in draft state)"),
				"variable":    stringSchema("the variable name without braces (e.g. 'deal_amount')"),
				refField:      stringSchema("source entity id"),
				pathField:     stringSchema("dotted JSON path inside the entity (e.g. 'deal.amount')"),
				"fallback":    stringSchema("optional literal returned when the source resolves empty"),
			}, []string{"document_id", "variable", refField, pathField}),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				u, _ := auth.FromContext(r.Context())
				raw := map[string]any{}
				if err := json.Unmarshal(args, &raw); err != nil {
					return nil, err
				}
				return runBind(r, d, u.OrgID, &u.UserID, raw, kind, refField, pathField)
			},
		}
	}

	s.RegisterTool(bindHandler("bind_variable_to_crm_deal", resolver.SourceCRMDeal, "deal_id", "path"))
	s.RegisterTool(bindHandler("bind_variable_to_crm_contact", resolver.SourceCRMContact, "contact_id", "path"))
	s.RegisterTool(bindHandler("bind_variable_to_scanner_finding", resolver.SourceScannerFind, "scan_id", "path"))

	s.RegisterTool(ToolDef{
		Name:        "bind_variable_to_org_setting",
		Write:       true,
		Description: "Bind a {{variable}} to a Hash org-level setting. path is one of org.name, org.plan, org.id, branding.* (when 8.5 lands).",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid (must be in draft state)"),
			"variable":    stringSchema("the variable name without braces"),
			"path":        stringSchema("setting key, e.g. 'org.name'"),
			"fallback":    stringSchema("optional literal if the setting is empty"),
		}, []string{"document_id", "variable", "path"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			raw := map[string]any{}
			if err := json.Unmarshal(args, &raw); err != nil {
				return nil, err
			}
			// org.setting bindings have no source_ref; reuse runBind by
			// injecting an empty deal_id-shaped key.
			raw["deal_id"] = ""
			return runBind(r, d, u.OrgID, &u.UserID, raw, resolver.SourceOrgSetting, "deal_id", "path")
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "unbind_variable",
		Write:       true,
		Description: "Remove a variable binding. The variable's static value (if any) and any agent override remain.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid (must be in draft state)"),
			"variable":    stringSchema("the variable name to unbind"),
		}, []string{"document_id", "variable"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
				Variable   string `json:"variable"`
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
			doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			if doc.Status != "draft" {
				return nil, fmt.Errorf("bindings frozen (status=%s)", doc.Status)
			}
			if err := d.Queries.DeleteVariableBinding(r.Context(), generated.DeleteVariableBindingParams{
				DocumentID: id, VariableName: p.Variable,
			}); err != nil {
				return nil, err
			}
			_, _ = d.Audit.Log(r.Context(), audit.Entry{
				OrgID:       u.OrgID,
				ActorUserID: &u.UserID,
				DocumentID:  &id,
				Kind:        audit.KindDocumentUpdated,
				Payload:     map[string]any{"via": "mcp", "tool": "unbind_variable", "variable": p.Variable},
			})
			return map[string]any{"unbound": p.Variable}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "preview_resolved_variables",
		Description: "Resolve every variable binding on a doc and return the final variable map plus a per-binding ResolveReport. On non-draft docs runs in FreezeMode (last_value cached at send time, no live fetches).",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"agent_overrides": map[string]any{
				"type":                 "object",
				"additionalProperties": map[string]any{"type": "string"},
				"description":          "optional k/v map that wins over every other layer (mirrors ResolveOptions.AgentOverrides)",
			},
		}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID     string            `json:"document_id"`
				AgentOverrides map[string]string `json:"agent_overrides"`
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
			doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			opts := resolver.ResolveOptions{AgentOverrides: p.AgentOverrides}
			if doc.Status != "draft" {
				opts.FreezeMode = true
			}
			vars, report, err := d.Resolver.Resolve(r.Context(), doc, opts)
			if err != nil {
				return nil, err
			}
			return map[string]any{"variables": vars, "report": report, "frozen": opts.FreezeMode}, nil
		},
	})
}

func runBind(r *http.Request, d Deps, orgID uuid.UUID, userID *uuid.UUID, args map[string]any, kind resolver.SourceKind, refField, pathField string) (any, error) {
	docIDStr, _ := args["document_id"].(string)
	id, err := uuid.Parse(docIDStr)
	if err != nil {
		return nil, errors.New("document_id must be a uuid")
	}
	variable, _ := args["variable"].(string)
	if variable == "" {
		return nil, errors.New("variable required")
	}
	ref, _ := args[refField].(string)
	path, _ := args[pathField].(string)
	if path == "" {
		return nil, fmt.Errorf("%s required", pathField)
	}
	if kind != resolver.SourceOrgSetting && ref == "" {
		return nil, fmt.Errorf("%s required", refField)
	}
	fallback, _ := args["fallback"].(string)

	doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("document not found")
	}
	if err != nil {
		return nil, err
	}
	if doc.Status != "draft" {
		return nil, fmt.Errorf("bindings frozen (status=%s)", doc.Status)
	}
	row, err := d.Queries.UpsertVariableBinding(r.Context(), generated.UpsertVariableBindingParams{
		DocumentID:   id,
		VariableName: variable,
		SourceKind:   string(kind),
		SourceRef:    ref,
		SourcePath:   path,
		Fallback:     fallback,
	})
	if err != nil {
		return nil, err
	}
	_, _ = d.Audit.Log(r.Context(), audit.Entry{
		OrgID:       orgID,
		ActorUserID: userID,
		DocumentID:  &id,
		Kind:        audit.KindDocumentUpdated,
		Payload: map[string]any{
			"via":         "mcp",
			"tool":        "bind_variable_to_" + string(kind),
			"variable":    variable,
			"source_kind": string(kind),
		},
	})
	return bindingRow(row), nil
}

func bindingRow(b *generated.DocumentVariableBinding) map[string]any {
	out := map[string]any{
		"variable":    b.VariableName,
		"source_kind": b.SourceKind,
		"source_ref":  b.SourceRef,
		"source_path": b.SourcePath,
		"fallback":    b.Fallback,
		"last_value":  b.LastValue,
		"last_error":  b.LastError,
		"updated_at":  b.UpdatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if b.LastResolved.Valid {
		out["last_resolved"] = b.LastResolved.Time.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return out
}
