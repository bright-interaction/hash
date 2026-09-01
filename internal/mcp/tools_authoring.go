// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/docintake"
	"github.com/bright-interaction/hash/internal/magictoken"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/requestmeta"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/versions"
)

var (
	errMCPRecipientDocumentNotFound = errors.New("document not found")
	errMCPRecipientNotFound         = errors.New("recipient not found")
	errMCPRecipientNotDraft         = errors.New("document not in draft state")
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
			"variables_json": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "string variable values keyed by name (eg. {\"recipient.name\":\"Tom\"})"},
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
			if p.SourceKind == "blocks" {
				if _, err := blocks.ParseVariableValues(vars); err != nil {
					return nil, fmt.Errorf("invalid variables_json: %w", err)
				}
			}

			switch p.SourceKind {
			case "blocks":
				blockTree := p.BlocksJSON
				if len(blockTree) == 0 {
					blockTree = json.RawMessage(`{"version":1,"blocks":[]}`)
				}
				// Normalize so generated block IDs are persisted once rather than
				// being regenerated on every read/render.
				normalized, err := blocks.NormalizeTreeJSON(blockTree)
				if err != nil {
					return nil, fmt.Errorf("invalid blocks_json: %w", err)
				}
				blockTree = normalized
				doc, err := audit.CommitMutation(r.Context(), d.Pool, d.Audit,
					func(q *generated.Queries) (*generated.Document, error) {
						if err := d.Billing.LockDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
							return nil, err
						}
						doc, err := q.CreateBlocksDocument(r.Context(), generated.CreateBlocksDocumentParams{
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
						if d.Versions != nil {
							if _, err := versions.New(q).Snapshot(r.Context(), versions.SnapshotInput{
								DocumentID: doc.ID, OrgID: doc.OrgID, Name: doc.Name, SourceKind: doc.SourceKind,
								BlocksJSON: doc.BlocksJson, VariablesJS: doc.VariablesJson, CreatedBy: &u.UserID,
								Via: versions.ViaMCP, Summary: "create_document",
							}); err != nil {
								return nil, err
							}
						}
						if err := d.Billing.EnforceDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
							return nil, err
						}
						return doc, nil
					},
					func(doc *generated.Document) audit.Entry {
						return audit.Entry{
							OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &doc.ID,
							Kind:    audit.KindDocumentCreated,
							Payload: map[string]any{"name": p.Name, "source_kind": "blocks", "via": "mcp", "tool": "create_document"},
						}
					},
				)
				if err != nil {
					return nil, err
				}
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
				rep, err := sanitize.SyntheticTemplateReport()
				if err != nil {
					return nil, err
				}
				doc, err := audit.CommitMutation(r.Context(), d.Pool, d.Audit,
					func(q *generated.Queries) (*generated.Document, error) {
						if err := d.Billing.LockDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
							return nil, err
						}
						doc, err := q.CreatePDFDocument(r.Context(), generated.CreatePDFDocumentParams{
							OrgID:                       u.OrgID,
							TemplateID:                  tmplID,
							Name:                        p.Name,
							PdfStorageKey:               tpl.PdfStorageKey,
							PdfSha256:                   tpl.PdfSha256,
							PdfStorageVersionID:         tpl.PdfStorageVersionID,
							EvidenceVersionPinsRequired: tpl.EvidenceVersionPinRequired,
							SenderID:                    u.UserID,
						})
						if err != nil {
							return nil, err
						}
						if err := q.UpdateMetadataRedactionReport(r.Context(), generated.UpdateMetadataRedactionReportParams{
							ID: doc.ID, MetadataRedactionReport: rep,
						}); err != nil {
							return nil, err
						}
						if err := d.Billing.EnforceDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
							return nil, err
						}
						return doc, nil
					},
					func(doc *generated.Document) audit.Entry {
						return audit.Entry{
							OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &doc.ID,
							Kind:    audit.KindDocumentCreated,
							Payload: map[string]any{"name": p.Name, "source_kind": "pdf", "via": "mcp", "tool": "create_document"},
						}
					},
				)
				if err != nil {
					return nil, err
				}
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
			if d.Pool == nil || d.Audit == nil {
				return nil, errors.New("atomic audit dependencies unavailable")
			}
			tx, err := d.Pool.Begin(r.Context())
			if err != nil {
				return nil, err
			}
			defer func() { _ = tx.Rollback(r.Context()) }()
			q := d.Queries.WithTx(tx)
			if err := d.Billing.LockDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
				return nil, err
			}
			doc, pageCount, err := docintake.CreatePDFSourceDocument(r.Context(), q, d.Storage, u.OrgID, u.UserID, p.Name, data)
			if err != nil {
				return nil, err
			}
			if err := d.Billing.EnforceDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
				if cleanupErr := cleanupMCPImportedPDF(r.Context(), d, doc.PdfStorageKey.String); cleanupErr != nil {
					slog.Error("mcp document quota rollback object cleanup failed", "quota_err", err, "cleanup_err", cleanupErr)
					return nil, errors.New("document import rollback cleanup failed")
				}
				return nil, err
			}
			// Acknowledgement mode: opt this draft out of requiring a signature
			// so recipients view + accept instead of signing.
			if p.RequiresSignature != nil && !*p.RequiresSignature {
				updated, uerr := q.SetDocumentRequiresSignature(r.Context(), generated.SetDocumentRequiresSignatureParams{
					ID: doc.ID, OrgID: u.OrgID, RequiresSignature: false,
				})
				if uerr != nil {
					cleanupErr := cleanupMCPImportedPDF(r.Context(), d, doc.PdfStorageKey.String)
					return nil, errors.Join(uerr, cleanupErr)
				}
				doc = updated
			}
			pending, err := d.Audit.LogTx(r.Context(), tx, audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &doc.ID,
				Kind:    audit.KindDocumentCreated,
				Payload: map[string]any{"name": p.Name, "source_kind": "pdf", "via": "mcp", "tool": "create_pdf_document"},
			})
			if err != nil {
				cleanupErr := cleanupMCPImportedPDF(r.Context(), d, doc.PdfStorageKey.String)
				return nil, errors.Join(err, cleanupErr)
			}
			if err := tx.Commit(r.Context()); err != nil {
				cleanupErr := cleanupMCPImportedPDF(r.Context(), d, doc.PdfStorageKey.String)
				return nil, errors.Join(err, cleanupErr)
			}
			d.Audit.Publish(pending)
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
			tree, err := blocks.ParseTree(p.BlocksJSON)
			if err != nil {
				return nil, fmt.Errorf("invalid blocks_json: %w", err)
			}
			return mutateDocumentTree(r, d, u.OrgID, u.UserID, id, versions.ViaMCP, "set_document_blocks", func(current *blocks.Tree) error {
				*current = *tree
				return nil
			})
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
			return mutateDocumentTree(r, d, u.OrgID, u.UserID, id, versions.ViaImport, "import_html", func(current *blocks.Tree) error {
				*current = *tree
				return nil
			})
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
			return mutateDocumentTree(r, d, u.OrgID, u.UserID, id, versions.ViaImport, "import_markdown", func(current *blocks.Tree) error {
				*current = *tree
				return nil
			})
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
			doc, err := mutateDocumentTree(r, d, u.OrgID, u.UserID, id, versions.ViaMCP, "append_block",
				func(t *blocks.Tree) error {
					t.Blocks = append(t.Blocks, blk)
					return blocks.Validate(t)
				})
			return doc, err
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "update_block",
		Write:       true,
		Description: "Replace a top-level block by id on a draft document. The replacement keeps the requested block_id.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"block_id":    stringSchema("id of the top-level block to replace"),
			"block":       map[string]any{"type": "object", "description": "replacement canonical block; see hash://schema/blocks"},
		}, []string{"document_id", "block_id", "block"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string          `json:"document_id"`
				BlockID    string          `json:"block_id"`
				Block      json.RawMessage `json:"block"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if p.BlockID == "" {
				return nil, errors.New("block_id required")
			}
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			var replacement blocks.Block
			if err := json.Unmarshal(p.Block, &replacement); err != nil {
				return nil, fmt.Errorf("invalid block: %w", err)
			}
			return mutateDocumentTree(r, d, u.OrgID, u.UserID, id, versions.ViaMCP, "update_block",
				func(t *blocks.Tree) error {
					return updateTopLevelBlock(t, p.BlockID, replacement)
				})
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
			doc, err := mutateDocumentTree(r, d, u.OrgID, u.UserID, id, versions.ViaMCP, "delete_block",
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
			doc, err := mutateDocumentTree(r, d, u.OrgID, u.UserID, id, versions.ViaMCP, "reorder_blocks",
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
			"required":       map[string]any{"type": "boolean", "const": true, "default": true, "description": "signature fields are always required"},
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
			return mutateDocumentTree(r, d, u.OrgID, u.UserID, id, versions.ViaMCP, "add_signature_field",
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
			"variables":   map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "name → string value map"},
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
			vars := p.Variables
			if len(vars) == 0 {
				vars = json.RawMessage(`{}`)
			}
			if _, err := blocks.ParseVariableValues(vars); err != nil {
				return nil, fmt.Errorf("invalid variables: %w", err)
			}
			if d.Pool == nil || d.Audit == nil {
				return nil, errors.New("atomic audit dependencies unavailable")
			}
			tx, err := d.Pool.Begin(r.Context())
			if err != nil {
				return nil, err
			}
			defer func() { _ = tx.Rollback(r.Context()) }()
			q := d.Queries.WithTx(tx)
			existing, err := q.GetDocumentForUpdate(r.Context(), generated.GetDocumentForUpdateParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			if existing.Status != "draft" || existing.SourceKind != "blocks" {
				return nil, errors.New("document not editable (must be draft + blocks-source)")
			}
			doc, err := q.UpdateDocumentBlocks(r.Context(), generated.UpdateDocumentBlocksParams{
				ID: id, OrgID: u.OrgID, BlocksJson: existing.BlocksJson, VariablesJson: vars,
			})
			if err != nil {
				return nil, err
			}
			if d.Versions != nil {
				if _, err := versions.New(q).Snapshot(r.Context(), versions.SnapshotInput{
					DocumentID: doc.ID, OrgID: doc.OrgID, Name: doc.Name, SourceKind: doc.SourceKind,
					BlocksJSON: doc.BlocksJson, VariablesJS: doc.VariablesJson, CreatedBy: &u.UserID,
					Via: versions.ViaMCP, Summary: "set_variables",
				}); err != nil {
					return nil, err
				}
			}
			pending, err := d.Audit.LogTx(r.Context(), tx, audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &id,
				Kind:    audit.KindDocumentUpdated,
				Payload: map[string]any{"via": "mcp", "tool": "set_variables"},
			})
			if err != nil {
				return nil, err
			}
			if err := tx.Commit(r.Context()); err != nil {
				return nil, err
			}
			d.Audit.Publish(pending)
			return doc, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "add_recipient",
		Write:       true,
		Description: "Add a signer, approver, or custom signature-role participant to a draft document. Informational cc/viewer delivery is unavailable in this release.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"role":        map[string]any{"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,63}$", "default": "signer", "description": "signer, approver, or a custom role matching a signature field; cc/viewer are unavailable"},
			"email":       stringSchema("recipient email"),
			"name":        stringSchema("recipient display name"),
			"order_index": intSchema("ordering for sequential routing; 0 for parallel", 0, 1000, 0),
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
			values, err := recipients.Normalize(recipients.Values{
				Email: p.Email, Name: p.Name, Role: role, OrderIndex: p.OrderIndex, Locale: locale,
			})
			if err != nil {
				return nil, err
			}
			if err := recipients.ValidateResponseRole(values.Role); err != nil {
				return nil, err
			}
			_, hash, err := auth.MintMagicToken()
			if err != nil {
				return nil, fmt.Errorf("mint token: %w", err)
			}
			rec, err := audit.CommitMutation(r.Context(), d.Pool, d.Audit,
				func(q *generated.Queries) (*generated.Recipient, error) {
					if err := d.Billing.LockDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
						return nil, err
					}
					rec, err := q.CreateRecipient(r.Context(), generated.CreateRecipientParams{
						DocumentID:          id,
						Role:                values.Role,
						Email:               values.Email,
						Name:                values.Name,
						OrderIndex:          values.OrderIndex,
						Locale:              values.Locale,
						MagicTokenHash:      hash,
						MagicTokenExpiresAt: magictoken.Expiry(doc.ExpiresAt, time.Now()),
					})
					if err != nil {
						return nil, err
					}
					if err := d.Billing.EnforceDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
						return nil, err
					}
					return rec, nil
				},
				func(rec *generated.Recipient) audit.Entry {
					return audit.Entry{
						OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &id, RecipientID: &rec.ID,
						Kind:    audit.KindRecipientCreated,
						Payload: map[string]any{"via": "mcp", "tool": "add_recipient", "email": rec.Email, "name": rec.Name, "role": rec.Role},
					}
				},
			)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not in draft state")
			}
			if err != nil {
				return nil, err
			}
			return rec, nil
		},
	})

	// update_recipient / delete_recipient: let an agent self-correct a mistyped
	// email or a wrongly-added signer BEFORE send, without a REST/UI fallback.
	// Draft-only so a link is never already out; only supplied fields change.
	s.RegisterTool(ToolDef{
		Name:        "update_recipient",
		Write:       true,
		Description: "Update a response participant on a DRAFT document (fix email/name/signature role/order/locale). Only supplied fields change; cc/viewer delivery is unavailable.",
		InputSchema: schemaObject(map[string]any{
			"document_id":  stringSchema("document uuid (must be draft)"),
			"recipient_id": stringSchema("recipient uuid"),
			"email":        stringSchema("optional new email"),
			"name":         stringSchema("optional new name"),
			"role":         map[string]any{"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,63}$", "description": "optional signer, approver, or custom signature role; cc/viewer are unavailable"},
			"order_index":  intSchema("optional new signing order", 0, 1000, 0),
			"locale":       stringSchema("optional new signer-ceremony locale"),
		}, []string{"document_id", "recipient_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID  string  `json:"document_id"`
				RecipientID string  `json:"recipient_id"`
				Email       *string `json:"email"`
				Name        *string `json:"name"`
				Role        *string `json:"role"`
				OrderIndex  *int32  `json:"order_index"`
				Locale      *string `json:"locale"`
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
			rec, err := audit.CommitMutation(r.Context(), d.Pool, d.Audit,
				func(q *generated.Queries) (*generated.Recipient, error) {
					doc, err := q.GetDocumentForUpdate(r.Context(), generated.GetDocumentForUpdateParams{ID: docID, OrgID: u.OrgID})
					if errors.Is(err, pgx.ErrNoRows) {
						return nil, errMCPRecipientDocumentNotFound
					}
					if err != nil {
						return nil, err
					}
					if doc.Status != "draft" {
						return nil, errMCPRecipientNotDraft
					}
					existing, err := q.GetRecipient(r.Context(), generated.GetRecipientParams{ID: rid, OrgID: u.OrgID})
					if errors.Is(err, pgx.ErrNoRows) || (err == nil && existing.DocumentID != docID) {
						return nil, errMCPRecipientNotFound
					}
					if err != nil {
						return nil, err
					}
					values, err := normalizeMCPRecipientUpdate(existing, p.Email, p.Name, p.Role, p.OrderIndex, p.Locale)
					if err != nil {
						return nil, err
					}
					return q.UpdateRecipient(r.Context(), generated.UpdateRecipientParams{
						ID: rid, DocumentID: docID, Email: values.Email, Name: values.Name,
						Role: values.Role, OrderIndex: values.OrderIndex, Locale: values.Locale,
					})
				},
				func(updated *generated.Recipient) audit.Entry {
					return audit.Entry{
						OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &docID, RecipientID: &rid,
						Kind:    audit.KindRecipientUpdated,
						Payload: map[string]any{"via": "mcp", "tool": "update_recipient", "email": updated.Email, "name": updated.Name, "role": updated.Role},
					}
				},
			)
			if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, errMCPRecipientNotDraft) {
				return nil, errMCPRecipientNotDraft
			}
			if err != nil {
				return nil, err
			}
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
			_, err = audit.CommitMutation(r.Context(), d.Pool, d.Audit,
				func(q *generated.Queries) (*generated.Recipient, error) {
					doc, err := q.GetDocumentForUpdate(r.Context(), generated.GetDocumentForUpdateParams{ID: docID, OrgID: u.OrgID})
					if errors.Is(err, pgx.ErrNoRows) {
						return nil, errMCPRecipientDocumentNotFound
					}
					if err != nil {
						return nil, err
					}
					if doc.Status != "draft" {
						return nil, errMCPRecipientNotDraft
					}
					existing, err := q.GetRecipient(r.Context(), generated.GetRecipientParams{ID: rid, OrgID: u.OrgID})
					if errors.Is(err, pgx.ErrNoRows) || (err == nil && existing.DocumentID != docID) {
						return nil, errMCPRecipientNotFound
					}
					if err != nil {
						return nil, err
					}
					if _, err := q.DeleteRecipient(r.Context(), generated.DeleteRecipientParams{ID: rid, DocumentID: docID}); err != nil {
						return nil, err
					}
					return existing, nil
				},
				func(deleted *generated.Recipient) audit.Entry {
					return audit.Entry{
						OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &docID, RecipientID: &rid,
						Kind:    audit.KindRecipientDeleted,
						Payload: map[string]any{"via": "mcp", "tool": "delete_recipient", "email": deleted.Email, "name": deleted.Name, "role": deleted.Role},
					}
				},
			)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("document not in draft state or recipient not found")
				}
				return nil, err
			}
			return map[string]any{"deleted": rid.String()}, nil
		},
	})
}

func normalizeMCPRecipientUpdate(existing *generated.Recipient, email, name, role *string, orderIndex *int32, locale *string) (recipients.Values, error) {
	values := recipients.Values{
		Email: existing.Email, Name: existing.Name, Role: existing.Role,
		OrderIndex: existing.OrderIndex, Locale: existing.Locale,
	}
	if email != nil {
		values.Email = *email
	}
	if name != nil {
		values.Name = *name
	}
	if role != nil {
		values.Role = *role
	}
	if orderIndex != nil {
		values.OrderIndex = *orderIndex
	}
	if locale != nil {
		values.Locale = *locale
	}
	normalized, err := recipients.Normalize(values)
	if err != nil {
		return recipients.Values{}, err
	}
	if err := recipients.ValidateResponseRole(normalized.Role); err != nil {
		return recipients.Values{}, err
	}
	return normalized, nil
}

// mutateDocumentTree applies fn to the document's block tree under a draft +
// blocks-source guard, persists the result, and emits the audit event.
func mutateDocumentTree(r *http.Request, d Deps, orgID, userID uuid.UUID, docID uuid.UUID, via versions.Via, toolName string, fn func(t *blocks.Tree) error) (any, error) {
	if d.Pool == nil || d.Audit == nil {
		return nil, errors.New("atomic audit dependencies unavailable")
	}
	tx, err := d.Pool.Begin(r.Context())
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	q := d.Queries.WithTx(tx)
	existing, err := q.GetDocumentForUpdate(r.Context(), generated.GetDocumentForUpdateParams{ID: docID, OrgID: orgID})
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
	doc, err := q.UpdateDocumentBlocks(r.Context(), generated.UpdateDocumentBlocksParams{
		ID: docID, OrgID: orgID, BlocksJson: raw, VariablesJson: existing.VariablesJson,
	})
	if err != nil {
		return nil, err
	}
	if d.Versions != nil {
		if _, err := versions.New(q).Snapshot(r.Context(), versions.SnapshotInput{
			DocumentID: doc.ID, OrgID: doc.OrgID, Name: doc.Name, SourceKind: doc.SourceKind,
			BlocksJSON: doc.BlocksJson, VariablesJS: doc.VariablesJson, CreatedBy: &userID,
			Via: via, Summary: toolName,
		}); err != nil {
			return nil, err
		}
	}
	pending, err := d.Audit.LogTx(r.Context(), tx, audit.Entry{
		OrgID: orgID, ActorUserID: &userID, DocumentID: &docID,
		Kind:    audit.KindDocumentUpdated,
		Payload: map[string]any{"via": "mcp", "tool": toolName, "blocks": len(tree.Blocks)},
	})
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(r.Context()); err != nil {
		return nil, err
	}
	d.Audit.Publish(pending)
	return doc, nil
}

func updateTopLevelBlock(tree *blocks.Tree, blockID string, replacement blocks.Block) error {
	if tree == nil {
		return errors.New("block tree is nil")
	}
	for i := range tree.Blocks {
		if tree.Blocks[i].ID == blockID {
			// A block's identity comes from the path argument, matching the REST
			// endpoint and preventing an update from silently becoming a rename.
			replacement.ID = blockID
			tree.Blocks[i] = replacement
			return blocks.Validate(tree)
		}
	}
	return errors.New("block_id not found at top level")
}

func clientIP(r *http.Request) string {
	// chi.middleware.RealIP has already put the client IP into r.RemoteAddr.
	return requestmeta.ClientIP(r.RemoteAddr)
}

func cleanupMCPImportedPDF(parent context.Context, d Deps, key string) error {
	if d.Storage == nil || key == "" {
		return errors.New("document import cleanup unavailable")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 15*time.Second)
	defer cancel()
	return d.Storage.Delete(ctx, key)
}
