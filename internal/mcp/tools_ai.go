package mcp

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/brightinteraction/hash/internal/ai"
	"github.com/brightinteraction/hash/internal/auth"
)

// registerAITools mounts the Phase 8.4 AI runtime read surface for agents.
// ai_runtime_status returns provider availability + shield state without
// firing any completions. The actual generation tools (clarify, draft
// counter, bilingual check) ship in Phase 11 with their own audit hooks.
func registerAITools(s *Server, d Deps) {
	if d.AIRuntime == nil {
		return
	}

	s.RegisterTool(ToolDef{
		Name:        "ai_runtime_status",
		Description: "Inspect the AI runtime configuration: registered providers, default, shield activation state, embedder, registered prompt count. No PII, no usage data, safe to call freely.",
		InputSchema: schemaObject(map[string]any{}, nil),
		Handler: func(r *http.Request, _ json.RawMessage) (any, error) {
			_, _ = auth.FromContext(r.Context())
			st := d.AIRuntime.Status()
			return map[string]any{
				"shield_active": st.ShieldActive,
				"providers":     st.Providers,
				"default":       st.Default,
				"embedder":      st.Embedder,
				"prompt_count":  st.PromptCount,
			}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "ai_list_prompts",
		Description: "List every registered prompt template (name, latest version, description). Agents can fetch a prompt's metadata before invoking it; the bodies themselves are not exposed (they're under our control, not the agent's).",
		InputSchema: schemaObject(map[string]any{}, nil),
		Handler: func(r *http.Request, _ json.RawMessage) (any, error) {
			_, _ = auth.FromContext(r.Context())
			entries := d.AIRuntime.PromptReg.List()
			out := make([]map[string]any, 0, len(entries))
			for _, e := range entries {
				out = append(out, map[string]any{
					"name":           e.Name,
					"latest_version": e.LatestVersion,
					"description":    e.Description,
				})
			}
			return map[string]any{"prompts": out, "count": len(out)}, nil
		},
	})
}

// guard against the import being dropped when the file is briefly empty.
var _ = ai.Status{}
var _ = errors.New
