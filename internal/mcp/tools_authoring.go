package mcp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/blocks"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/docintake"
	"github.com/brightinteraction/hash/internal/magictoken"
	"github.com/brightinteraction/hash/internal/render"
)

// pgtypeUUID lifts a uuid.UUID into pgx's nullable form.
func pgtypeUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// registerAuthoringTools mounts the agent-facing write tools. Every tool
// emits an audit event with `via=mcp` and the tool name so we can tell
// agent-authored vs human-authored documents apart.
func registerAuthoringTools(s *Server, d Deps) {
	s.RegisterTool(ToolDef{
		Name:        "create_document",
		Write:       true,
		Description: "Create a new draft document. Use source_kind=blocks for the agent authoring path; source_kind=pdf with template_id for stamping flows.",
		InputSchema: schemaObject(map[string]any{
			"name":           stringSchema("human-readable document name"),
			"source_kind":    map[string]any{"type": "string", "enum": []string{"blocks", "pdf"}, "description": "blocks (agent) or pdf (uploaded template)"},
			"template_id":    stringSchema("optional template uuid to instantiate from"),
			"variables_json": map[string]any{"type": "object", "description": "variable values keyed by name (eg. {\"recipient.name\":\"Tom\"})"},
			"blocks_json":    map[string]any{"type": "object", "description": "initial block tree {version:1,blocks:[...]} when source_kind=blocks"},
		}, []string{"name", "source_kind"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				Name          string          `json:"name"`
				SourceKind    string          `json:"source_kind"`
				TemplateID    string          `json:"template_id"`
				BlocksJSON    json.RawMessage `json:"blocks_json"`
				VariablesJSON json.RawMessage `json:"variables_json"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			if p.Name == "" {
				return nil, errors.New("name required")
			}
			if p.SourceKind != "blocks" && p.SourceKind != "pdf" {
				return nil, errors.New("source_kind must be 'blocks' or 'pdf'")
			}

			var tmplID pgtype.UUID
			if p.TemplateID != "" {
				id, err := uuid.Parse(p.TemplateID)
				if err != nil {
					return nil, errors.New("template_id must be a uuid")
				}
				tmplID = pgtypeUUID(id)
			}

			vars := p.VariablesJSON
			if len(vars) == 0 {
				vars = json.RawMessage(`{}`)
			}

			switch p.SourceKind {
			case "blocks":
				blockTree := p.BlocksJSON
				if len(blockTree) == 0 {
					blockTree = json.RawMessage(`{"version":1,"blocks":[]}`)
				}
				// Parse + validate so a malformed agent payload returns a
				// precise error before we touch the DB.
				if _, err := blocks.ParseTree(blockTree); err != nil {
					return nil, fmt.Errorf("invalid blocks_json: %w", err)
				}
				doc, err := d.Queries.CreateBlocksDocument(r.Context(), generated.CreateBlocksDocumentParams{
					OrgID:         u.OrgID,
					TemplateID:    tmplID,
					Name:          p.Name,
					BlocksJson:    blockTree,
					VariablesJson: vars,
					SenderID:      u.UserID,
				})
				if err != nil {
					return nil, err
				}
				logMCPEvent(r, d, audit.Entry{
					OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &doc.ID,
					Kind:    audit.KindDocumentCreated,
					Payload: map[string]any{"name": p.Name, "source_kind": "blocks", "via": "mcp", "tool": "create_document"},
				})
				return doc, nil
			case "pdf":
				if !tmplID.Valid {
					return nil, errors.New("template_id required when source_kind=pdf")
				}
				tpl, err := d.Queries.GetTemplate(r.Context(), generated.GetTemplateParams{
					ID: uuid.UUID(tmplID.Bytes), OrgID: u.OrgID,
				})
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("template not found")
				}
				if err != nil || tpl.SourceKind != "pdf" {
					return nil, errors.New("template is not a pdf-source template")
				}
				doc, err := d.Queries.CreatePDFDocument(r.Context(), generated.CreatePDFDocumentParams{
					OrgID:         u.OrgID,
					TemplateID:    tmplID,
					Name:          p.Name,
					PdfStorageKey: tpl.PdfStorageKey,
					PdfSha256:     tpl.PdfSha256,
					SenderID:      u.UserID,
				})
				if err != nil {
					return nil, err
				}
				logMCPEvent(r, d, audit.Entry{
					OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &doc.ID,
					Kind:    audit.KindDocumentCreated,
					Payload: map[string]any{"name": p.Name, "source_kind": "pdf", "via": "mcp", "tool": "create_document"},
				})
				return doc, nil
			}
			return nil, errors.New("unreachable")
		},
	})

	s.RegisterTool(ToolDef{
		Name:  "create_pdf_document",
		Write: true,
		Description: "Create a signable pdf-source document in ONE step from a designed proposal, skipping the template detour. " +
			"Supply EITHER pdf_base64 (a base64-encoded PDF) OR html (a designed HTML page rendered to PDF with its own CSS/@page preserved). " +
			"Returns a draft pdf-source document; then add_recipient + add_document_field (type=signature) + send_document.",
		InputSchema: schemaObject(map[string]any{
			"name":               stringSchema("human-readable document name"),
			"pdf_base64":         stringSchema("base64-encoded PDF bytes (mutually exclusive with html)"),
			"html":               stringSchema("designed HTML to render to PDF (mutually exclusive with pdf_base64)"),
			"landscape":          map[string]any{"type": "boolean", "default": false, "description": "landscape fallback when the HTML sets no @page size"},
			"requires_signature": map[string]any{"type": "boolean", "default": true, "description": "false = acknowledgement mode (recipients view + accept, no signature)"},
		}, []string{"name"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				Name              string `json:"name"`
				PDFBase64         string `json:"pdf_base64"`
				HTML              string `json:"html"`
				Landscape         bool   `json:"landscape"`
				RequiresSignature *bool  `json:"requires_signature"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			if p.Name == "" {
				return nil, errors.New("name required")
			}
			if (p.PDFBase64 == "") == (p.HTML == "") {
				return nil, errors.New("supply exactly one of pdf_base64 or html")
			}
			var data []byte
			if p.PDFBase64 != "" {
				raw, derr := base64.StdEncoding.DecodeString(p.PDFBase64)
				if derr != nil {
					return nil, errors.New("pdf_base64 is not valid base64")
				}
				data = raw
			} else {
				if d.PDF == nil {
					return nil, errors.New("pdf renderer unavailable")
				}
				opts := render.PDFOptions{PreferCSSPageSize: true, WaitDelay: "1000ms"}
				if p.Landscape {
					opts.PaperWidth, opts.PaperHeight = 11.69, 8.27
				}
				rendered, rerr := d.PDF.HTMLToPDF(r.Context(), render.SanitizeForRender(p.HTML), opts)
				if rerr != nil {
					return nil, fmt.Errorf("render html to pdf: %w", rerr)
				}
				data = rendered
			}
			doc, pageCount, err := docintake.CreatePDFSourceDocument(r.Context(), d.Queries, d.Storage, u.OrgID, u.UserID, p.Name, data)
			if err != nil {
				return nil, err
			}
			// Acknowledgement mode: opt this draft out of requiring a signature
			// so recipients view + accept instead of signing.
			if p.RequiresSignature != nil && !*p.RequiresSignature {
				if updated, uerr := d.Queries.SetDocumentRequiresSignature(r.Context(), generated.SetDocumentRequiresSignatureParams{
					ID: doc.ID, OrgID: u.OrgID, RequiresSignature: false,
				}); uerr == nil {
					doc = updated
				}
			}
			logMCPEvent(r, d, audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &doc.ID,
				Kind:    audit.KindDocumentCreated,
				Payload: map[string]any{"name": p.Name, "source_kind": "pdf", "via": "mcp", "tool": "create_pdf_document"},
			})
			return map[string]any{"document": doc, "page_count": pageCount}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "set_document_blocks",
		Write:       true,
		Description: "Replace the entire block tree of a draft document. Validates against the canonical schema.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"blocks_json": map[string]any{"type": "object", "description": "{version:1, blocks:[...]}"},
		}, []string{"document_id", "blocks_json"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string          `json:"document_id"`
				BlocksJSON json.RawMessage `json:"blocks_json"`
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
			if _, err := blocks.ParseTree(p.BlocksJSON); err != nil {
				return nil, fmt.Errorf("invalid blocks_json: %w", err)
			}
			existing, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			if existing.Status != "draft" || existing.SourceKind != "blocks" {
				return nil, errors.New("document not editable (must be draft + blocks-source)")
			}
			doc, err := d.Queries.UpdateDocumentBlocks(r.Context(), generated.UpdateDocumentBlocksParams{
				ID: id, OrgID: u.OrgID,
				BlocksJson:    p.BlocksJSON,
				VariablesJson: existing.VariablesJson,
			})
			if err != nil {
				return nil, err
			}
			logMCPEvent(r, d, audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &id,
				Kind:    audit.KindDocumentUpdated,
				Payload: map[string]any{"via": "mcp", "tool": "set_document_blocks"},
			})
			return doc, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "import_html",
		Write:       true,
		Description: "Replace a draft document's block tree by parsing an HTML fragment into canonical blocks.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"html":        stringSchema("HTML fragment to parse into blocks"),
		}, []string{"document_id", "html"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
				HTML       string `json:"html"`
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
			tree := blocks.ParseHTML(p.HTML)
			raw, err := json.Marshal(tree)
			if err != nil {
				return nil, err
			}
			existing, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			if existing.Status != "draft" || existing.SourceKind != "blocks" {
				return nil, errors.New("document not editable (must be draft + blocks-source)")
			}
			doc, err := d.Queries.UpdateDocumentBlocks(r.Context(), generated.UpdateDocumentBlocksParams{
				ID: id, OrgID: u.OrgID, BlocksJson: raw, VariablesJson: existing.VariablesJson,
			})
			if err != nil {
				return nil, err
			}
			logMCPEvent(r, d, audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &id,
				Kind:    audit.KindDocumentUpdated,
				Payload: map[string]any{"via": "mcp", "tool": "import_html", "blocks": len(tree.Blocks)},
			})
			return doc, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "import_markdown",
		Write:       true,
		Description: "Replace a draft document's block tree by parsing a markdown body into canonical blocks.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"markdown":    stringSchema("markdown source"),
		}, []string{"document_id", "markdown"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
				Markdown   string `json:"markdown"`
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
			tree := blocks.ParseMarkdown(p.Markdown)
			raw, err := json.Marshal(tree)
			if err != nil {
				return nil, err
			}
			existing, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			if existing.Status != "draft" || existing.SourceKind != "blocks" {
				return nil, errors.New("document not editable (must be draft + blocks-source)")
			}
			doc, err := d.Queries.UpdateDocumentBlocks(r.Context(), generated.UpdateDocumentBlocksParams{
				ID: id, OrgID: u.OrgID, BlocksJson: raw, VariablesJson: existing.VariablesJson,
			})
			if err != nil {
				return nil, err
			}
			logMCPEvent(r, d, audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &id,
				Kind:    audit.KindDocumentUpdated,
				Payload: map[string]any{"via": "mcp", "tool": "import_markdown", "blocks": len(tree.Blocks)},
			})
			return doc, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "append_block",
		Write:       true,
		Description: "Append a block to the end of a draft document's block tree.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"block":       map[string]any{"type": "object", "description": "canonical block; see hash://schema/blocks"},
		}, []string{"document_id", "block"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string          `json:"document_id"`
				Block      json.RawMessage `json:"block"`
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
			var blk blocks.Block
			if err := json.Unmarshal(p.Block, &blk); err != nil {
				return nil, fmt.Errorf("invalid block: %w", err)
			}
			doc, err := mutateDocumentTree(r, d, u.OrgID, u.UserID, id, "append_block",
				func(t *blocks.Tree) error {
					t.Blocks = append(t.Blocks, blk)
					return blocks.Validate(t)
				})
			return doc, err
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "delete_block",
		Write:       true,
		Description: "Remove a block by id from a draft document.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"block_id":    stringSchema("id of the block to remove"),
		}, []string{"document_id", "block_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
				BlockID    string `json:"block_id"`
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
			doc, err := mutateDocumentTree(r, d, u.OrgID, u.UserID, id, "delete_block",
				func(t *blocks.Tree) error {
					filtered := make([]blocks.Block, 0, len(t.Blocks))
					removed := false
					for _, b := range t.Blocks {
						if b.ID == p.BlockID {
							removed = true
							continue
						}
						filtered = append(filtered, b)
					}
					if !removed {
						return errors.New("block_id not found at top level")
					}
					t.Blocks = filtered
					return nil
				})
			return doc, err
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "reorder_blocks",
		Write:       true,
		Description: "Rearrange the top-level blocks of a draft document. block_ids must be a permutation of the existing ids.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"block_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, []string{"document_id", "block_ids"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string   `json:"document_id"`
				BlockIDs   []string `json:"block_ids"`
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
			doc, err := mutateDocumentTree(r, d, u.OrgID, u.UserID, id, "reorder_blocks",
				func(t *blocks.Tree) error {
					byID := map[string]blocks.Block{}
					for _, b := range t.Blocks {
						byID[b.ID] = b
					}
					if len(p.BlockIDs) != len(t.Blocks) {
						return errors.New("block_ids length must equal top-level block count")
					}
					reordered := make([]blocks.Block, 0, len(p.BlockIDs))
					seen := map[string]bool{}
					for _, bid := range p.BlockIDs {
						b, ok := byID[bid]
						if !ok || seen[bid] {
							return fmt.Errorf("unknown or duplicate block_id: %s", bid)
						}
						seen[bid] = true
						reordered = append(reordered, b)
					}
					t.Blocks = reordered
					return nil
				})
			return doc, err
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "add_signature_field",
		Write:       true,
		Description: "Convenience: append a signature_field block bound to a recipient role.",
		InputSchema: schemaObject(map[string]any{
			"document_id":    stringSchema("document uuid"),
			"recipient_role": stringSchema("role label, must match a recipient on the document (eg 'client', 'provider')"),
			"label":          stringSchema("optional human label, eg 'Client signature'"),
			"required":       map[string]any{"type": "boolean", "default": true},
		}, []string{"document_id", "recipient_role"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID    string `json:"document_id"`
				RecipientRole string `json:"recipient_role"`
				Label         string `json:"label"`
				Required      *bool  `json:"required"`
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
			required := true
			if p.Required != nil {
				required = *p.Required
			}
			block := blocks.Block{
				Type: blocks.TypeSignatureField,
				Attrs: map[string]any{
					"recipient_role": p.RecipientRole,
					"label":          p.Label,
					"required":       required,
				},
			}
			return mutateDocumentTree(r, d, u.OrgID, u.UserID, id, "add_signature_field",
				func(t *blocks.Tree) error {
					t.Blocks = append(t.Blocks, block)
					return blocks.Validate(t)
				})
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "set_variables",
		Write:       true,
		Description: "Replace a draft document's variable values.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"variables":   map[string]any{"type": "object", "description": "name → value map"},
		}, []string{"document_id", "variables"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string          `json:"document_id"`
				Variables  json.RawMessage `json:"variables"`
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
			existing, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			if existing.Status != "draft" {
				return nil, errors.New("document not editable")
			}
			vars := p.Variables
			if len(vars) == 0 {
				vars = json.RawMessage(`{}`)
			}
			doc, err := d.Queries.UpdateDocumentBlocks(r.Context(), generated.UpdateDocumentBlocksParams{
				ID: id, OrgID: u.OrgID, BlocksJson: existing.BlocksJson, VariablesJson: vars,
			})
			if err != nil {
				return nil, err
			}
			logMCPEvent(r, d, audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &id,
				Kind:    audit.KindDocumentUpdated,
				Payload: map[string]any{"via": "mcp", "tool": "set_variables"},
			})
			return doc, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "add_recipient",
		Write:       true,
		Description: "Add a signer (or other-role) recipient to a draft document.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"role":        map[string]any{"type": "string", "enum": []string{"signer", "approver", "cc", "viewer"}, "default": "signer"},
			"email":       stringSchema("recipient email"),
			"name":        stringSchema("recipient display name"),
			"order_index": map[string]any{"type": "integer", "default": 0, "description": "ordering for sequential routing; 0 for parallel"},
			"locale":      stringSchema("signing language code (e.g. sv, en); defaults to the document's default_locale"),
		}, []string{"document_id", "email", "name"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
				Role       string `json:"role"`
				Email      string `json:"email"`
				Name       string `json:"name"`
				OrderIndex int32  `json:"order_index"`
				Locale     string `json:"locale"`
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
			role := p.Role
			if role == "" {
				role = "signer"
			}
			// Cross-tenant + draft check.
			doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			if doc.Status != "draft" {
				return nil, errors.New("document not in draft state")
			}
			_, hash, err := auth.MintMagicToken()
			if err != nil {
				return nil, fmt.Errorf("mint token: %w", err)
			}
			// Inherit the document's default signing language unless the caller
			// passed one. Mirrors the REST handleCreateRecipient cascade so
			// MCP-driven sends never silently fall back to English on a
			// Swedish document (this column was missing here before).
			locale := p.Locale
			if locale == "" {
				locale = doc.DefaultLocale
			}
			if locale == "" {
				locale = "en"
			}
			rec, err := d.Queries.CreateRecipient(r.Context(), generated.CreateRecipientParams{
				DocumentID:     id,
				Role:           role,
				Email:          p.Email,
				Name:           p.Name,
				OrderIndex:     p.OrderIndex,
				Locale:         locale,
				MagicTokenHash: hash,
				// Bound the link from creation. The REST handleCreateRecipient
				// sets this; the MCP path used to omit it, leaving a NULL
				// (fail-open) expiry until the doc was sent.
				MagicTokenExpiresAt: magictoken.Expiry(doc.ExpiresAt, time.Now()),
			})
			if err != nil {
				return nil, err
			}
			logMCPEvent(r, d, audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &id, RecipientID: &rec.ID,
				Kind:    audit.KindRecipientInvited,
				Payload: map[string]any{"via": "mcp", "tool": "add_recipient", "email": p.Email, "name": p.Name, "role": role},
			})
			return rec, nil
		},
	})

	// update_recipient / delete_recipient: let an agent self-correct a mistyped
	// email or a wrongly-added signer BEFORE send, without a REST/UI fallback.
	// Draft-only so a link is never already out; only supplied fields change.
	s.RegisterTool(ToolDef{
		Name:        "update_recipient",
		Write:       true,
		Description: "Update a recipient on a DRAFT document (fix a typo'd email, change name/role/order/locale). Only supplied fields change.",
		InputSchema: schemaObject(map[string]any{
			"document_id":  stringSchema("document uuid (must be draft)"),
			"recipient_id": stringSchema("recipient uuid"),
			"email":        stringSchema("optional new email"),
			"name":         stringSchema("optional new name"),
			"role":         stringSchema("optional new role (signer|viewer|approver|cc)"),
			"order_index":  intSchema("optional new signing order", 0, 1000, 0),
			"locale":       stringSchema("optional new signer-ceremony locale"),
		}, []string{"document_id", "recipient_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID  string `json:"document_id"`
				RecipientID string `json:"recipient_id"`
				Email       string `json:"email"`
				Name        string `json:"name"`
				Role        string `json:"role"`
				OrderIndex  *int32 `json:"order_index"`
				Locale      string `json:"locale"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			docID, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			rid, err := uuid.Parse(p.RecipientID)
			if err != nil {
				return nil, errors.New("recipient_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), docID); err != nil {
				return nil, err
			}
			doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			if doc.Status != "draft" {
				return nil, errors.New("document not in draft state")
			}
			existing, err := d.Queries.GetRecipient(r.Context(), generated.GetRecipientParams{ID: rid, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("recipient not found")
			}
			if err != nil {
				return nil, err
			}
			if existing.DocumentID != docID {
				return nil, errors.New("recipient does not belong to this document")
			}
			email := existing.Email
			if p.Email != "" {
				email = p.Email
			}
			name := existing.Name
			if p.Name != "" {
				name = p.Name
			}
			role := existing.Role
			if p.Role != "" {
				role = p.Role
			}
			orderIdx := existing.OrderIndex
			if p.OrderIndex != nil {
				orderIdx = *p.OrderIndex
			}
			locale := existing.Locale
			if p.Locale != "" {
				locale = p.Locale
			}
			rec, err := d.Queries.UpdateRecipient(r.Context(), generated.UpdateRecipientParams{
				ID: rid, DocumentID: docID, Email: email, Name: name, Role: role, OrderIndex: orderIdx, Locale: locale,
			})
			if err != nil {
				return nil, err
			}
			logMCPEvent(r, d, audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &docID, RecipientID: &rid,
				Kind:    audit.KindDocumentUpdated,
				Payload: map[string]any{"via": "mcp", "tool": "update_recipient"},
			})
			return rec, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "delete_recipient",
		Write:       true,
		Description: "Remove a recipient from a DRAFT document (e.g. a mistakenly-added signer). Draft-only.",
		InputSchema: schemaObject(map[string]any{
			"document_id":  stringSchema("document uuid (must be draft)"),
			"recipient_id": stringSchema("recipient uuid"),
		}, []string{"document_id", "recipient_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID  string `json:"document_id"`
				RecipientID string `json:"recipient_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			docID, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			rid, err := uuid.Parse(p.RecipientID)
			if err != nil {
				return nil, errors.New("recipient_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), docID); err != nil {
				return nil, err
			}
			doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			if doc.Status != "draft" {
				return nil, errors.New("document not in draft state")
			}
			if err := d.Queries.DeleteRecipient(r.Context(), generated.DeleteRecipientParams{ID: rid, DocumentID: docID}); err != nil {
				return nil, err
			}
			logMCPEvent(r, d, audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &docID, RecipientID: &rid,
				Kind:    audit.KindDocumentUpdated,
				Payload: map[string]any{"via": "mcp", "tool": "delete_recipient"},
			})
			return map[string]any{"deleted": rid.String()}, nil
		},
	})
}

// mutateDocumentTree applies fn to the document's block tree under a draft +
// blocks-source guard, persists the result, and emits the audit event.
func mutateDocumentTree(r *http.Request, d Deps, orgID, userID uuid.UUID, docID uuid.UUID, toolName string, fn func(t *blocks.Tree) error) (any, error) {
	existing, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("document not found")
	}
	if err != nil {
		return nil, err
	}
	if existing.Status != "draft" || existing.SourceKind != "blocks" {
		return nil, errors.New("document not editable (must be draft + blocks-source)")
	}
	tree, err := blocks.ParseTree(existing.BlocksJson)
	if err != nil {
		return nil, fmt.Errorf("existing blocks_json invalid: %w", err)
	}
	if err := fn(tree); err != nil {
		return nil, err
	}
	if err := blocks.Validate(tree); err != nil {
		return nil, fmt.Errorf("post-edit validation: %w", err)
	}
	raw, err := json.Marshal(tree)
	if err != nil {
		return nil, err
	}
	doc, err := d.Queries.UpdateDocumentBlocks(r.Context(), generated.UpdateDocumentBlocksParams{
		ID: docID, OrgID: orgID, BlocksJson: raw, VariablesJson: existing.VariablesJson,
	})
	if err != nil {
		return nil, err
	}
	logMCPEvent(r, d, audit.Entry{
		OrgID: orgID, ActorUserID: &userID, DocumentID: &docID,
		Kind:    audit.KindDocumentUpdated,
		Payload: map[string]any{"via": "mcp", "tool": toolName, "blocks": len(tree.Blocks)},
	})
	return doc, nil
}

func logMCPEvent(r *http.Request, d Deps, e audit.Entry) {
	if d.Audit == nil {
		return
	}
	if e.IP == "" {
		e.IP = clientIP(r)
	}
	if e.UserAgent == "" {
		e.UserAgent = r.UserAgent()
	}
	_, _ = d.Audit.Log(r.Context(), e)
}

func clientIP(r *http.Request) string {
	// chi.middleware.RealIP has already put the client IP into r.RemoteAddr.
	host := r.RemoteAddr
	if i := lastIndex(host, ':'); i >= 0 {
		return host[:i]
	}
	return host
}

func lastIndex(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}
