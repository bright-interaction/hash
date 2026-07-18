// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/eidas"
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
		Description: "Create a routing rule. predicate_json shape: {field, op, value} OR {all: [...]} OR {any: [...]}. Field is 'amount', 'country', 'document_type', or 'variables.<key>'. Op is >=, >, <=, <, ==, !=, in.",
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
			active := true
			if p.Active != nil {
				active = *p.Active
			}
			row, err := d.Queries.InsertEIDASRule(r.Context(), generated.InsertEIDASRuleParams{
				OrgID:         u.OrgID,
				Name:          p.Name,
				Priority:      p.Priority,
				PredicateJson: p.Predicate,
				RequiredTier:  p.RequiredTier,
				Reason:        p.Reason,
				Active:        active,
			})
			if err != nil {
				return nil, err
			}
			_, _ = d.Audit.Log(r.Context(), audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID,
				Kind:    audit.KindDocumentUpdated,
				Payload: map[string]any{"via": "mcp", "tool": "create_eidas_rule", "rule_id": row.ID.String()},
			})
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
			if err := d.Queries.DeleteEIDASRule(r.Context(), generated.DeleteEIDASRuleParams{ID: id, OrgID: u.OrgID}); err != nil {
				return nil, err
			}
			return map[string]any{"deleted": id.String()}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "seed_swedish_eidas_defaults",
		Write:       true,
		MinRole:     auth.RoleOwner, // REST eIDAS rule writes are owner-only
		Description: "Insert the default Swedish rule set (100k SEK -> AES, 1M SEK -> QES, healthcare -> AES). Idempotent: existing rules with the same names are left untouched.",
		InputSchema: schemaObject(map[string]any{}, nil),
		Handler: func(r *http.Request, _ json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			if err := d.EIDAS.SeedSwedishDefaults(r.Context(), u.OrgID); err != nil {
				return nil, err
			}
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
		Description: "Pin a document's routing tier (SES/AES/QES). Senders use this to pre-commit to a higher tier than the rules would require; the send guard then accepts the send instead of refusing.",
		InputSchema: schemaObject(map[string]any{
			"document_id":  stringSchema("document uuid"),
			"routing_tier": stringSchema("'SES' | 'AES' | 'QES'"),
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
			if !eidas.Tier(p.RoutingTier).Valid() {
				return nil, errors.New("routing_tier must be SES, AES, or QES")
			}
			if _, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID}); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("document not found")
				}
				return nil, err
			}
			if err := d.Queries.SetDocumentRoutingTier(r.Context(), generated.SetDocumentRoutingTierParams{
				ID: id, OrgID: u.OrgID, RoutingTier: p.RoutingTier,
			}); err != nil {
				return nil, err
			}
			return map[string]any{"document_id": id.String(), "routing_tier": p.RoutingTier}, nil
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
