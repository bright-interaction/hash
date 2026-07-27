// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/http"

	"github.com/bright-interaction/hash/internal/ai"
)

// GET /api/v1/ai/status
//
// Operator-only read of the AI runtime configuration. No PII, no usage
// data. The audit + cost reads come in Phase 8.4.1; this is the boot
// confirmation.
func (s *Server) handleAIStatus(w http.ResponseWriter, r *http.Request) {
	_, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if s.AIRuntime == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured":    false,
			"shield_active": false,
			"providers":     []string{},
			"default":       "",
			"embedder":      "",
			"prompt_count":  0,
		})
		return
	}
	st := s.AIRuntime.Status()
	prompts := s.AIRuntime.PromptReg.List()
	promptOut := make([]map[string]any, 0, len(prompts))
	for _, p := range prompts {
		promptOut = append(promptOut, map[string]any{
			"name":           p.Name,
			"latest_version": p.LatestVersion,
			"description":    p.Description,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured":    true,
		"shield_active": st.ShieldActive,
		"providers":     st.Providers,
		"default":       st.Default,
		"embedder":      st.Embedder,
		"prompts":       promptOut,
	})
}

// guard against the import being dropped if the file is briefly empty.
var _ = ai.Status{}
