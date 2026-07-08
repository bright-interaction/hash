package mcp

import (
	"net/http"

	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/blocks"
	"github.com/brightinteraction/hash/internal/db/generated"
)

func registerResources(s *Server, d Deps) {
	s.RegisterResource(Resource{
		URI:         "hash://meta/capabilities",
		Name:        "Hash capabilities",
		Description: "Tool catalogue, scopes, policy, and what is intentionally NOT exposed via MCP.",
		MimeType:    "application/json",
		Loader: func(r *http.Request) (any, error) {
			return capabilitiesPayload(s), nil
		},
	})

	s.RegisterResource(Resource{
		URI:         "hash://schema/blocks",
		Name:        "Block tree schema",
		Description: "Canonical block schema. Read this once at session start so write tools produce valid output.",
		MimeType:    "application/json",
		Loader: func(r *http.Request) (any, error) {
			return blocks.SchemaJSON(), nil
		},
	})

	s.RegisterResource(Resource{
		URI:         "hash://users/me",
		Name:        "Caller identity",
		Description: "Identity attached to the API key making this MCP session.",
		MimeType:    "application/json",
		Loader: func(r *http.Request) (any, error) {
			u, _ := auth.FromContext(r.Context())
			return map[string]any{
				"user_id": u.UserID,
				"org_id":  u.OrgID,
				"email":   u.Email,
				"role":    u.Role,
			}, nil
		},
	})

	s.RegisterResource(Resource{
		URI:         "hash://documents/recent",
		Name:        "Recent documents",
		Description: "Last 50 documents in this org, newest first.",
		MimeType:    "application/json",
		Loader: func(r *http.Request) (any, error) {
			u, _ := auth.FromContext(r.Context())
			rows, err := d.Queries.ListDocuments(r.Context(), generated.ListDocumentsParams{
				OrgID: u.OrgID, Column2: nil, Limit: 50, Offset: 0,
			})
			if err != nil {
				return nil, err
			}
			return map[string]any{"documents": rows}, nil
		},
	})

	s.RegisterResource(Resource{
		URI:         "hash://events/recent",
		Name:        "Recent events",
		Description: "Last 100 audit events in this org. Includes via=mcp marker for agent-authored edits.",
		MimeType:    "application/json",
		Loader: func(r *http.Request) (any, error) {
			u, _ := auth.FromContext(r.Context())
			rows, err := d.Queries.ListRecentEventsByOrg(r.Context(), generated.ListRecentEventsByOrgParams{
				OrgID: u.OrgID, Limit: 100,
			})
			if err != nil {
				return nil, err
			}
			return map[string]any{"events": rows}, nil
		},
	})
}

// capabilitiesPayload self-describes the MCP surface so a host LLM can
// reason about what it can and cannot do without trial-and-error.
func capabilitiesPayload(s *Server) map[string]any {
	tools := make([]map[string]any, 0, len(s.tools))
	for _, t := range s.tools {
		tools = append(tools, map[string]any{
			"name":        t.Name,
			"description": t.Description,
		})
	}
	return map[string]any{
		"product": "hash",
		"version": "0.1.0",
		"phase":   "1",
		"exposed": map[string]any{
			"tools_count":     len(s.tools),
			"resources_count": len(s.resources),
			"prompts_count":   len(s.prompts),
			"tools":           tools,
		},
		"intentionally_not_exposed": []string{
			"raw recipient magic-link tokens (only token hashes are stored anyway)",
			"signer signature image bytes (presigned URLs only)",
			"webhook signing secrets",
			"audit-cert ed25519 private key",
			"any cross-org data",
		},
		"out_of_scope": []string{
			"webhook endpoint config (use the REST surface at /api/v1/webhooks)",
			"api-key minting (use the REST surface at /api/v1/api-keys)",
			"OIDC / Zitadel administration",
		},
		"policy": map[string]any{
			"org_scoped":   "every tool runs under the API key owner's org_id; cross-tenant queries return not-found",
			"audit_trail":  "every write fires an event with via=mcp + tool name; readable via hash://events/recent",
			"draft_only":   "block edits require status=draft; sent or completed documents are immutable to authoring tools",
			"agent_marker": "documents authored or edited via MCP are tagged in the audit trail so reviewers can filter",
		},
	}
}
