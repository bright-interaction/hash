// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
)

// registerEIDASTools mounts the Phase 9.2 routing-rules surface for
// agents. Rules describe predicates over document metadata + resolved
// variables and require a minimum tier (SES/AES/QES); on send, the
// highest matched tier gates the flow.
func registerEIDASTools(s *Server, d Deps) {
	if d.EIDAS == nil {
		return
	}

	s.RegisterTool(ToolDef{
		Name:        "list_eidas_rules",
		MinRole:     auth.RoleOwner,
		Description: "Return every eIDAS routing rule for the caller's org (active + inactive), sorted by active then priority.",
		InputSchema: schemaObject(map[string]any{}, nil),
		Handler: func(r *http.Request, _ json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			rules, err := d.Queries.ListEIDASRules(r.Context(), u.OrgID)
			if err != nil {
				return nil, err
			}
			out := make([]map[string]any, 0, len(rules))
			for _, r := range rules {
				out = append(out, ruleRow(r))
			}
			return map[string]any{"rules": out, "count": len(out)}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "create_eidas_rule",
		Write:       true,
		MinRole:     auth.RoleOwner, // REST eIDAS rule writes are owner-only; a permissive/deleted rule downgrades the required signature tier (QES->SES)
		Description: "Create a routing rule. Only SES rules may be active in this release; inactive AES/QES rules may be retained for migration or deletion. predicate_json shape: {field, op, value} OR {all: [...]} OR {any: [...]}",
		InputSchema: schemaObject(map[string]any{
			"name":           stringSchema("display name"),
			"priority":       intSchema("informational priority (lower = evaluated first)", 0, 1000, 100),
			"predicate_json": map[string]any{"type": "object", "description": "predicate tree (see description)"},
			"required_tier":  stringSchema("'SES' | 'AES' | 'QES'"),
			"reason":         stringSchema("human-readable explanation surfaced in send-blocked errors"),
			"active":         map[string]any{"type": "boolean", "description": "default true"},
		}, []string{"name", "predicate_json", "required_tier"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				Name         string          `json:"name"`
				Priority     int32           `json:"priority"`
				Predicate    json.RawMessage `json:"predicate_json"`
				RequiredTier string          `json:"required_tier"`
				Reason       string          `json:"reason"`
				Active       *bool           `json:"active"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			if !eidas.Tier(p.RequiredTier).Valid() {
				return nil, errors.New("required_tier must be SES, AES, or QES")
			}
			if err := eidas.ValidateRule(p.Predicate, eidas.Tier(p.RequiredTier)); err != nil {
				return nil, fmt.Errorf("invalid eIDAS rule: %w", err)
			}
			active := true
			if p.Active != nil {
				active = *p.Active
			}
			if err := eidas.ValidateRuleActivation(eidas.Tier(p.RequiredTier), active); err != nil {
				return nil, err
			}
			row, err := audit.CommitMutation(r.Context(), d.Pool, d.Audit,
				func(q *generated.Queries) (*generated.EidasRoutingRule, error) {
					return q.InsertEIDASRule(r.Context(), generated.InsertEIDASRuleParams{
						OrgID:         u.OrgID,
						Name:          p.Name,
						Priority:      p.Priority,
						PredicateJson: p.Predicate,
						RequiredTier:  p.RequiredTier,
						Reason:        p.Reason,
						Active:        active,
					})
				},
				func(row *generated.EidasRoutingRule) audit.Entry {
					return audit.Entry{
						OrgID: u.OrgID, ActorUserID: &u.UserID,
						Kind:    audit.KindDocumentUpdated,
						Payload: map[string]any{"via": "mcp", "tool": "create_eidas_rule", "rule_id": row.ID.String()},
					}
				},
			)
			if err != nil {
				return nil, err
			}
			return ruleRow(row), nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "delete_eidas_rule",
		Write:       true,
		MinRole:     auth.RoleOwner, // REST eIDAS rule writes are owner-only
		Description: "Delete a routing rule by ID.",
		InputSchema: schemaObject(map[string]any{
			"rule_id": stringSchema("rule uuid"),
		}, []string{"rule_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				RuleID string `json:"rule_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.RuleID)
			if err != nil {
				return nil, errors.New("rule_id must be a uuid")
			}
			_, err = audit.CommitMutation(r.Context(), d.Pool, d.Audit,
				func(q *generated.Queries) (uuid.UUID, error) {
					if _, err := q.GetEIDASRule(r.Context(), generated.GetEIDASRuleParams{ID: id, OrgID: u.OrgID}); err != nil {
						return uuid.Nil, err
					}
					return id, q.DeleteEIDASRule(r.Context(), generated.DeleteEIDASRuleParams{ID: id, OrgID: u.OrgID})
				},
				func(uuid.UUID) audit.Entry {
					return audit.Entry{
						OrgID: u.OrgID, ActorUserID: &u.UserID,
						Kind:    audit.KindDocumentUpdated,
						Payload: map[string]any{"via": "mcp", "tool": "delete_eidas_rule", "rule_id": id.String()},
					}
				},
			)
			if err != nil {
				return nil, err
			}
			return map[string]any{"deleted": id.String()}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "seed_swedish_eidas_defaults",
		Write:       true,
		MinRole:     auth.RoleOwner, // REST eIDAS rule writes are owner-only
		Description: "Unavailable in this SES-only release. The historic Swedish defaults require AES/QES and are retained only as an explicit fail-closed compatibility surface.",
		InputSchema: schemaObject(map[string]any{}, nil),
		Handler: func(r *http.Request, _ json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			if err := eidas.ValidateRuleActivation(eidas.TierAES, true); err != nil {
				return nil, fmt.Errorf("Swedish defaults are unavailable: %w", err)
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
			if err := eidas.New(q).SeedSwedishDefaults(r.Context(), u.OrgID); err != nil {
				return nil, err
			}
			pending, err := d.Audit.LogTx(r.Context(), tx, audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID,
				Kind:    audit.KindDocumentUpdated,
				Payload: map[string]any{"via": "mcp", "tool": "seed_swedish_eidas_defaults"},
			})
			if err != nil {
				return nil, err
			}
			if err := tx.Commit(r.Context()); err != nil {
				return nil, err
			}
			d.Audit.Publish(pending)
			rules, _ := d.Queries.ListEIDASRules(r.Context(), u.OrgID)
			out := make([]map[string]any, 0, len(rules))
			for _, r := range rules {
				out = append(out, ruleRow(r))
			}
			return map[string]any{"rules": out, "count": len(out)}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "preview_eidas_rules",
		MinRole:     auth.RoleOwner,
		Description: "Run the eIDAS engine against a hypothetical input without committing a send. Returns required_tier + matched_rules so an agent can show 'this contract at amount=200000 would require AES'.",
		InputSchema: schemaObject(map[string]any{
			"amount":        map[string]any{"type": "number", "description": "deal amount (numeric)"},
			"country":       stringSchema("ISO country code or jurisdiction string"),
			"document_type": stringSchema("document type label"),
			"variables": map[string]any{
				"type":                 "object",
				"additionalProperties": map[string]any{"type": "string"},
			},
			"current_tier": stringSchema("optional 'SES' | 'AES' | 'QES' to see if would_block=true"),
		}, nil),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				Amount       float64           `json:"amount"`
				Country      string            `json:"country"`
				DocumentType string            `json:"document_type"`
				Variables    map[string]string `json:"variables"`
				CurrentTier  string            `json:"current_tier"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			if p.Variables == nil {
				p.Variables = map[string]string{}
			}
			decision, err := d.EIDAS.Evaluate(r.Context(), u.OrgID, eidas.EvaluateInput{
				Amount:       p.Amount,
				Country:      p.Country,
				DocumentType: p.DocumentType,
				Variables:    p.Variables,
			})
			if err != nil {
				return nil, err
			}
			out := map[string]any{
				"required_tier":   decision.RequiredTier,
				"matched_rules":   decision.MatchedRules,
				"evaluated_count": decision.EvaluatedCount,
			}
			if p.CurrentTier != "" {
				out["would_block"] = eidas.Tier(p.CurrentTier).Cmp(decision.RequiredTier) < 0
			}
			return out, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "set_document_routing_tier",
		Write:       true,
		Description: "Pin a draft document to SES. AES/QES are rejected until those ceremony tiers are production-capable.",
		InputSchema: schemaObject(map[string]any{
			"document_id":  stringSchema("document uuid"),
			"routing_tier": stringSchema("'SES' only in this release"),
		}, []string{"document_id", "routing_tier"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID  string `json:"document_id"`
				RoutingTier string `json:"routing_tier"`
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
			tier := strings.ToUpper(strings.TrimSpace(p.RoutingTier))
			if tier != string(eidas.TierSES) {
				return nil, errors.New("AES and QES are unavailable until identity proofs are cryptographically bound to the ceremony; routing_tier must be SES")
			}
			tx, err := d.Pool.Begin(r.Context())
			if err != nil {
				return nil, err
			}
			defer func() { _ = tx.Rollback(r.Context()) }()
			q := d.Queries.WithTx(tx)
			rows, err := q.SetDocumentRoutingTier(r.Context(), generated.SetDocumentRoutingTierParams{
				ID: id, OrgID: u.OrgID, RoutingTier: tier,
			})
			if err != nil {
				return nil, err
			}
			if rows != 1 {
				return nil, errors.New("routing tier can only be set to SES while the document is draft")
			}
			pendingAudit, err := d.Audit.LogTx(r.Context(), tx, audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &id,
				Kind: audit.KindDocumentUpdated,
				Payload: map[string]any{
					"via": "mcp", "tool": "set_document_routing_tier", "routing_tier": tier,
				},
			})
			if err != nil {
				return nil, err
			}
			if err := tx.Commit(r.Context()); err != nil {
				return nil, err
			}
			d.Audit.Publish(pendingAudit)
			return map[string]any{"document_id": id.String(), "routing_tier": tier}, nil
		},
	})
}

func ruleRow(r *generated.EidasRoutingRule) map[string]any {
	return map[string]any{
		"id":             r.ID.String(),
		"name":           r.Name,
		"priority":       r.Priority,
		"predicate_json": json.RawMessage(r.PredicateJson),
		"required_tier":  r.RequiredTier,
		"reason":         r.Reason,
		"active":         r.Active,
		"created_at":     r.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		"updated_at":     r.UpdatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}
