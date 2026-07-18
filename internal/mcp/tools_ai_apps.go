// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/aiapps"
	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/blocks"
	"github.com/brightinteraction/hash/internal/db/generated"
)

// registerAIAppsTools mounts the Phase 11 AI moats: clarifier (11.1),
// negotiation copilot (11.2), bilingual equivalence (11.3).
func registerAIAppsTools(s *Server, d Deps) {
	if d.Clarifier != nil {
		s.RegisterTool(ToolDef{
			Name:        "clarify_clause",
			Description: "Return a plain-language explanation of a clause for a signer. Grounded in the supplied clause text + surrounding context + legal references; locale shapes the response language (sv-SE default). Shield-tokenizes PII before crossing to the model.",
			InputSchema: schemaObject(map[string]any{
				"document_id":         stringSchema("document uuid"),
				"clause_text":         stringSchema("the clause to explain"),
				"surrounding_context": stringSchema("optional neighbour clauses for grounding"),
				"legal_context":       stringSchema("optional legal references"),
				"question":            stringSchema("optional signer question; empty = 'explain this'"),
				"locale":              stringSchema("RFC 5646 tag; default sv-SE"),
			}, []string{"document_id", "clause_text"}),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				u, _ := auth.FromContext(r.Context())
				var p struct {
					DocumentID         string `json:"document_id"`
					ClauseText         string `json:"clause_text"`
					SurroundingContext string `json:"surrounding_context"`
					LegalContext       string `json:"legal_context"`
					Question           string `json:"question"`
					Locale             string `json:"locale"`
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
				res, err := d.Clarifier.Clarify(r.Context(), aiapps.ClarifyInput{
					OrgID:              u.OrgID,
					DocumentID:         id,
					UserID:             &u.UserID,
					Locale:             p.Locale,
					ClauseText:         p.ClauseText,
					SurroundingContext: p.SurroundingContext,
					LegalContext:       p.LegalContext,
					Question:           p.Question,
				})
				if err != nil {
					return nil, err
				}
				return res, nil
			},
		})
	}

	if d.Negotiator != nil {
		s.RegisterTool(ToolDef{
			Name:        "suggest_counter_clause",
			Write:       true,
			Description: "Draft a counter-clause for a flagged block. Returns revised text + rationale. The output is a suggestion only; pass it to propose_counter_clause to actually persist a proposal.",
			InputSchema: schemaObject(map[string]any{
				"document_id": stringSchema("document uuid"),
				"block_id":    stringSchema("block uuid to redraft"),
				"concern":     stringSchema("recipient concern / context"),
				"red_lines": map[string]any{
					"type":  "array",
					"items": map[string]any{"type": "string"},
				},
			}, []string{"document_id", "block_id"}),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				u, _ := auth.FromContext(r.Context())
				var p struct {
					DocumentID string   `json:"document_id"`
					BlockID    string   `json:"block_id"`
					Concern    string   `json:"concern"`
					RedLines   []string `json:"red_lines"`
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
				tree, err := blocks.ParseTree(doc.BlocksJson)
				if err != nil {
					return nil, err
				}
				var target *blocks.Block
				for i := range tree.Blocks {
					if tree.Blocks[i].ID == p.BlockID {
						target = &tree.Blocks[i]
						break
					}
				}
				if target == nil {
					return nil, errors.New("block_id not in document tree")
				}
				res, err := d.Negotiator.SuggestCounter(r.Context(), aiapps.CounterInput{
					OrgID:          u.OrgID,
					DocumentID:     id,
					UserID:         &u.UserID,
					OriginalClause: target.Text,
					Concern:        p.Concern,
					RedLines:       p.RedLines,
				})
				if err != nil {
					return nil, err
				}
				return res, nil
			},
		})

		s.RegisterTool(ToolDef{
			Name:        "propose_counter_clause",
			Write:       true,
			Description: "Persist a proposal against a block. proposal_kind is edit | reject | counter | block_lock. Set ai_assisted=true when the proposed_text came from suggest_counter_clause.",
			InputSchema: schemaObject(map[string]any{
				"document_id":   stringSchema("document uuid"),
				"block_id":      stringSchema("block uuid"),
				"proposal_kind": stringSchema("edit | reject | counter | block_lock"),
				"proposed_text": stringSchema("the proposed clause body"),
				"rationale":     stringSchema("one-line explanation"),
				"ai_assisted":   map[string]any{"type": "boolean"},
				"parent_id":     stringSchema("optional parent proposal in a counter-counter chain"),
			}, []string{"document_id", "block_id", "proposal_kind"}),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				u, _ := auth.FromContext(r.Context())
				var p struct {
					DocumentID   string `json:"document_id"`
					BlockID      string `json:"block_id"`
					ProposalKind string `json:"proposal_kind"`
					ProposedText string `json:"proposed_text"`
					Rationale    string `json:"rationale"`
					AIAssisted   bool   `json:"ai_assisted"`
					ParentID     string `json:"parent_id"`
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
				switch p.ProposalKind {
				case "edit", "reject", "counter", "block_lock":
				default:
					return nil, errors.New("proposal_kind must be edit | reject | counter | block_lock")
				}
				doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("document not found")
				}
				if err != nil {
					return nil, err
				}
				parent := pgtype.UUID{}
				if p.ParentID != "" {
					pid, err := uuid.Parse(p.ParentID)
					if err != nil {
						return nil, errors.New("parent_id must be a uuid")
					}
					parent = pgtype.UUID{Bytes: pid, Valid: true}
				}
				row, err := d.Queries.InsertProposal(r.Context(), generated.InsertProposalParams{
					DocumentID:   doc.ID,
					OrgID:        u.OrgID,
					ProposedBy:   pgtype.UUID{Bytes: u.UserID, Valid: true},
					BlockID:      p.BlockID,
					ProposalKind: p.ProposalKind,
					ProposedText: p.ProposedText,
					Rationale:    p.Rationale,
					DiffJson:     []byte("{}"),
					AiAssisted:   p.AIAssisted,
					ParentID:     parent,
				})
				if err != nil {
					return nil, err
				}
				_, _ = d.Audit.Log(r.Context(), audit.Entry{
					OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &doc.ID,
					Kind: "negotiation.proposed",
					Payload: map[string]any{
						"via": "mcp", "tool": "propose_counter_clause",
						"proposal_id": row.ID.String(), "block_id": p.BlockID, "kind": p.ProposalKind, "ai_assisted": p.AIAssisted,
					},
				})
				return proposalRow(row), nil
			},
		})

		s.RegisterTool(ToolDef{
			Name:        "set_proposal_status",
			Write:       true,
			Description: "Move a proposal between pending / accepted / rejected / superseded. Sender + recipient sides both call this; the audit log captures which side did it.",
			InputSchema: schemaObject(map[string]any{
				"proposal_id": stringSchema("proposal uuid"),
				"status":      stringSchema("pending | accepted | rejected | superseded"),
			}, []string{"proposal_id", "status"}),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				u, _ := auth.FromContext(r.Context())
				var p struct {
					ProposalID string `json:"proposal_id"`
					Status     string `json:"status"`
				}
				if err := MustParseArgs(args, &p); err != nil {
					return nil, err
				}
				id, err := uuid.Parse(p.ProposalID)
				if err != nil {
					return nil, errors.New("proposal_id must be a uuid")
				}
				// Confine a doc-scoped agent token: it must not flip a proposal on
				// a sibling document. Resolve the owning doc (org-scoped) first.
				ownerDoc, err := d.Queries.GetProposalOwnerDoc(r.Context(), generated.GetProposalOwnerDocParams{ID: id, OrgID: u.OrgID})
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("proposal not found")
				}
				if err != nil {
					return nil, err
				}
				if err := auth.EnforceDocScope(r.Context(), ownerDoc); err != nil {
					return nil, err
				}
				switch p.Status {
				case "pending", "accepted", "rejected", "superseded":
				default:
					return nil, errors.New("status must be pending | accepted | rejected | superseded")
				}
				row, err := d.Queries.SetProposalStatus(r.Context(), generated.SetProposalStatusParams{
					ID: id, OrgID: u.OrgID, Status: p.Status,
				})
				if err != nil {
					return nil, err
				}
				_, _ = d.Audit.Log(r.Context(), audit.Entry{
					OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &row.DocumentID,
					Kind:    "negotiation.status_changed",
					Payload: map[string]any{"via": "mcp", "proposal_id": id.String(), "status": p.Status},
				})
				return proposalRow(row), nil
			},
		})

		s.RegisterTool(ToolDef{
			Name:        "list_proposals",
			Description: "Return up to 200 proposals against a document, newest-first.",
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
				rows, err := d.Queries.ListProposalsByDocument(r.Context(), generated.ListProposalsByDocumentParams{
					DocumentID: id, Limit: 200,
				})
				if err != nil {
					return nil, err
				}
				out := make([]map[string]any, 0, len(rows))
				for _, p := range rows {
					out = append(out, proposalRow(p))
				}
				return map[string]any{"proposals": out, "count": len(out)}, nil
			},
		})
	}

	if d.RiskAnalyzer != nil {
		s.RegisterTool(ToolDef{
			Name:        "run_risk_analysis",
			Description: "Read the document's draft block tree and return a deterministic list of findings flagging elevated-risk clauses (liability, IP, auto_renewal, jurisdiction, payment_terms, termination, indemnification, confidentiality, data_protection, warranty). Each finding has block_id, category, severity (low|medium|high), summary, suggestion. Use this before sending high-value contracts to surface risks the sender may have missed.",
			InputSchema: schemaObject(map[string]any{
				"document_id":    stringSchema("document uuid"),
				"locale":         stringSchema("RFC 5646 tag, default sv-SE"),
				"sender_context": stringSchema("optional notes about sender redlines / industry"),
			}, []string{"document_id"}),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				u, _ := auth.FromContext(r.Context())
				var p struct {
					DocumentID    string `json:"document_id"`
					Locale        string `json:"locale"`
					SenderContext string `json:"sender_context"`
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
				if err != nil {
					if errors.Is(err, pgx.ErrNoRows) {
						return nil, errors.New("document not found")
					}
					return nil, err
				}
				tree, err := blocks.ParseTree(doc.BlocksJson)
				if err != nil {
					return nil, err
				}
				res, err := d.RiskAnalyzer.Analyze(r.Context(), aiapps.AnalyzeInput{
					OrgID: u.OrgID, DocumentID: id, UserID: &u.UserID,
					Locale: p.Locale, Blocks: tree.Blocks, SenderContext: p.SenderContext,
				})
				if err != nil {
					return nil, err
				}
				if d.Audit != nil {
					_, _ = d.Audit.Log(r.Context(), audit.Entry{
						OrgID: u.OrgID, DocumentID: &id, ActorUserID: &u.UserID,
						Kind: "risk.analyzed",
						Payload: map[string]any{
							"findings_count": len(res.Findings),
							"shield_active":  res.ShieldActive,
							"via":            "mcp",
						},
					})
				}
				return res, nil
			},
		})
	}

	if d.Bilingual != nil {
		s.RegisterTool(ToolDef{
			Name:        "check_bilingual_equivalence",
			Description: "Compare two clauses in different languages and return {equivalent, drift, confidence}. Use this to verify a translation hasn't dropped or weakened obligations across languages.",
			InputSchema: schemaObject(map[string]any{
				"document_id": stringSchema("document uuid"),
				"lang_a":      stringSchema("RFC 5646 tag, default sv-SE"),
				"clause_a":    stringSchema("clause body in lang_a"),
				"lang_b":      stringSchema("RFC 5646 tag, default en-GB"),
				"clause_b":    stringSchema("clause body in lang_b"),
			}, []string{"document_id", "clause_a", "clause_b"}),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				u, _ := auth.FromContext(r.Context())
				var p struct {
					DocumentID string `json:"document_id"`
					LangA      string `json:"lang_a"`
					ClauseA    string `json:"clause_a"`
					LangB      string `json:"lang_b"`
					ClauseB    string `json:"clause_b"`
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
				res, err := d.Bilingual.Check(r.Context(), aiapps.EquivalenceInput{
					OrgID: u.OrgID, DocumentID: id, UserID: &u.UserID,
					LangA: p.LangA, ClauseA: p.ClauseA, LangB: p.LangB, ClauseB: p.ClauseB,
				})
				if err != nil {
					return nil, err
				}
				return res, nil
			},
		})
	}
}

func proposalRow(p *generated.DocumentProposal) map[string]any {
	out := map[string]any{
		"id":            p.ID.String(),
		"document_id":   p.DocumentID.String(),
		"block_id":      p.BlockID,
		"proposal_kind": p.ProposalKind,
		"proposed_text": p.ProposedText,
		"rationale":     p.Rationale,
		"status":        p.Status,
		"ai_assisted":   p.AiAssisted,
		"created_at":    p.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		"updated_at":    p.UpdatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if p.ProposedBy.Valid {
		out["proposed_by"] = uuid.UUID(p.ProposedBy.Bytes).String()
	}
	if p.ParentID.Valid {
		out["parent_id"] = uuid.UUID(p.ParentID.Bytes).String()
	}
	return out
}
