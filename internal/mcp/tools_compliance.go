// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/compliance"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
)

// registerComplianceTools mounts the Phase 12 MCP surface: seed the
// baseline, list flags, transition flag status, manually trigger a
// flag-run sweep.
func registerComplianceTools(s *Server, d Deps) {
	if d.Compliance == nil {
		return
	}

	if d.Environment != "production" {
		s.RegisterTool(ToolDef{
			Name:        "seed_compliance_baseline",
			Write:       true,
			MinRole:     auth.RoleOwner, // REST compliance writes are owner-only
			Description: "Install the GDPR-baseline kit for the caller's org: DPA template + records of processing + Article 13 privacy notice + Swedish eIDAS rules. Idempotent. Business types: law_firm | saas | consulting | healthcare | fintech | other.",
			InputSchema: schemaObject(map[string]any{
				"business_type": stringSchema("business archetype (law_firm | saas | consulting | healthcare | fintech | other)"),
				"jurisdiction":  map[string]any{"type": "string", "enum": []string{"SE"}, "description": "supported jurisdiction; defaults to SE"},
			}, []string{"business_type"}),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				u, _ := auth.FromContext(r.Context())
				var p struct {
					BusinessType string `json:"business_type"`
					Jurisdiction string `json:"jurisdiction"`
				}
				if err := MustParseArgs(args, &p); err != nil {
					return nil, err
				}
				bt := compliance.BusinessType(p.BusinessType)
				if !bt.Valid() {
					return nil, errors.New("business_type must be law_firm | saas | consulting | healthcare | fintech | other")
				}
				jurisdiction, err := compliance.NormalizeJurisdiction(p.Jurisdiction)
				if err != nil {
					return nil, err
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
				res, err := compliance.New(q, eidas.New(q)).Seed(r.Context(), compliance.SeedInput{
					OrgID:        u.OrgID,
					UserID:       u.UserID,
					BusinessType: bt,
					Jurisdiction: jurisdiction,
				})
				if err != nil {
					return nil, err
				}
				pending, err := d.Audit.LogTx(r.Context(), tx, audit.Entry{
					OrgID: u.OrgID, ActorUserID: &u.UserID,
					Kind:    "compliance.baseline_seeded",
					Payload: map[string]any{"via": "mcp", "business_type": bt, "jurisdiction": jurisdiction},
				})
				if err != nil {
					return nil, err
				}
				if err := tx.Commit(r.Context()); err != nil {
					return nil, err
				}
				d.Audit.Publish(pending)
				return res, nil
			},
		})
	}

	s.RegisterTool(ToolDef{
		Name:        "get_compliance_baseline",
		MinRole:     auth.RoleOwner,
		Description: "Return the org's compliance baseline row (business type, jurisdiction, seeded artifact IDs).",
		InputSchema: schemaObject(map[string]any{}, nil),
		Handler: func(r *http.Request, _ json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			row, err := d.Queries.GetComplianceBaseline(r.Context(), u.OrgID)
			if errors.Is(err, pgx.ErrNoRows) {
				return map[string]any{"baseline": nil}, nil
			}
			if err != nil {
				return nil, err
			}
			return baselineRow(row), nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "list_compliance_flags",
		MinRole:     auth.RoleOwner,
		Description: "Return up to 500 compliance flags for the caller's org. Filter by status: open | acknowledged | resolved | dismissed (empty = all).",
		InputSchema: schemaObject(map[string]any{
			"status": stringSchema("optional status filter"),
		}, nil),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				Status string `json:"status"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			rows, err := d.Queries.ListComplianceFlags(r.Context(), generated.ListComplianceFlagsParams{
				OrgID:   u.OrgID,
				Column2: p.Status,
				Limit:   500,
			})
			if err != nil {
				return nil, err
			}
			out := make([]map[string]any, 0, len(rows))
			for _, f := range rows {
				out = append(out, flagRow(f))
			}
			return map[string]any{"flags": out, "count": len(out)}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "set_compliance_flag_status",
		Write:       true,
		MinRole:     auth.RoleOwner, // REST compliance writes are owner-only
		Description: "Move a flag through open -> acknowledged -> resolved | dismissed.",
		InputSchema: schemaObject(map[string]any{
			"flag_id": stringSchema("flag uuid"),
			"status":  stringSchema("open | acknowledged | resolved | dismissed"),
		}, []string{"flag_id", "status"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				FlagID string `json:"flag_id"`
				Status string `json:"status"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.FlagID)
			if err != nil {
				return nil, errors.New("flag_id must be a uuid")
			}
			switch p.Status {
			case "open", "acknowledged", "resolved", "dismissed":
			default:
				return nil, errors.New("status must be open|acknowledged|resolved|dismissed")
			}
			row, err := audit.CommitMutation(r.Context(), d.Pool, d.Audit,
				func(q *generated.Queries) (*generated.ComplianceFlag, error) {
					return q.SetComplianceFlagStatus(r.Context(), generated.SetComplianceFlagStatusParams{
						ID: id, OrgID: u.OrgID, Status: p.Status,
					})
				},
				func(*generated.ComplianceFlag) audit.Entry {
					return audit.Entry{
						OrgID: u.OrgID, ActorUserID: &u.UserID,
						Kind:    "compliance.flag_status_changed",
						Payload: map[string]any{"via": "mcp", "flag_id": id.String(), "status": p.Status},
					}
				},
			)
			if err != nil {
				return nil, err
			}
			return flagRow(row), nil
		},
	})
}

func baselineRow(b *generated.ComplianceBaseline) map[string]any {
	out := map[string]any{
		"org_id":        b.OrgID.String(),
		"business_type": b.BusinessType,
		"jurisdiction":  b.Jurisdiction,
		"seeded_at":     b.SeededAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		"updated_at":    b.UpdatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if b.DpaTemplateID.Valid {
		out["dpa_template_id"] = uuid.UUID(b.DpaTemplateID.Bytes).String()
	}
	if b.RecordsDocID.Valid {
		out["records_doc_id"] = uuid.UUID(b.RecordsDocID.Bytes).String()
	}
	if b.PrivacyNoticeID.Valid {
		out["privacy_notice_id"] = uuid.UUID(b.PrivacyNoticeID.Bytes).String()
	}
	return out
}

func flagRow(f *generated.ComplianceFlag) map[string]any {
	out := map[string]any{
		"id":               f.ID.String(),
		"org_id":           f.OrgID.String(),
		"update_ref":       f.UpdateRef,
		"update_title":     f.UpdateTitle,
		"affected_topic":   f.AffectedTopic,
		"block_id":         f.BlockID,
		"severity":         f.Severity,
		"suggested_action": f.SuggestedAction,
		"status":           f.Status,
		"raised_at":        f.RaisedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if f.DocumentID.Valid {
		out["document_id"] = uuid.UUID(f.DocumentID.Bytes).String()
	}
	if f.TemplateID.Valid {
		out["template_id"] = uuid.UUID(f.TemplateID.Bytes).String()
	}
	if f.ResolvedAt.Valid {
		out["resolved_at"] = f.ResolvedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return out
}
