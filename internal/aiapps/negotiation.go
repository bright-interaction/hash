// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package aiapps

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/brightinteraction/hash/internal/ai"
)

// Negotiator drafts counter-clauses for a contract under negotiation.
// Phase 11.2's negotiation copilot uses this to suggest revised wording
// when a recipient flags a clause as needing change. The output is a
// suggestion, never an auto-applied edit; the caller still walks the
// proposal through accept/reject/supersede.
type Negotiator struct {
	Runtime *ai.Runtime
}

// CounterInput is the per-call shape. RedLines is the sender's set of
// non-negotiable boundaries (e.g. "indemnification cap stays at $X",
// "IP assignment cannot be weakened"); the model is instructed to flag
// any change that would cross one rather than silently weakening.
type CounterInput struct {
	OrgID          uuid.UUID
	DocumentID     uuid.UUID
	UserID         *uuid.UUID
	OriginalClause string
	Concern        string
	RedLines       []string
}

// CounterResult is the suggestion + provenance.
type CounterResult struct {
	RevisedClause string `json:"revised_clause"`
	Rationale     string `json:"rationale"`
	RawText       string `json:"raw_text"` // full model output for callers that want it verbatim
	Provider      string `json:"provider"`
	Model         string `json:"model"`
	LatencyMs     int    `json:"latency_ms"`
	ShieldActive  bool   `json:"shield_active"`
}

// SuggestCounter renders the registered negotiation_counter prompt and
// runs it. Result splits the model output by the convention agreed in
// the prompt: revised body first, single-line rationale after. The full
// text is also returned so a strict caller can inspect the raw form.
func (n *Negotiator) SuggestCounter(ctx context.Context, in CounterInput) (CounterResult, error) {
	if n == nil || n.Runtime == nil {
		return CounterResult{}, errors.New("negotiator: AI runtime not configured")
	}
	if in.OriginalClause == "" {
		return CounterResult{}, errors.New("negotiator: original_clause required")
	}
	prompt, err := n.Runtime.PromptReg.Get("negotiation_counter", 0)
	if err != nil {
		return CounterResult{}, fmt.Errorf("negotiator: prompt: %w", err)
	}
	red := "(none specified)"
	if len(in.RedLines) > 0 {
		red = "- " + strings.Join(in.RedLines, "\n- ")
	}
	req, err := prompt.Render(map[string]string{
		"OriginalClause": in.OriginalClause,
		"Concern":        in.Concern,
		"RedLines":       red,
	})
	if err != nil {
		return CounterResult{}, err
	}
	resp, err := n.Runtime.Complete(ctx, req, ai.CompleteOptions{
		OrgID:      in.OrgID,
		DocumentID: &in.DocumentID,
		UserID:     in.UserID,
	})
	if err != nil {
		return CounterResult{}, err
	}
	revised, rationale := splitCounter(resp.Text)
	return CounterResult{
		RevisedClause: revised,
		Rationale:     rationale,
		RawText:       resp.Text,
		Provider:      resp.Provider,
		Model:         resp.Model,
		LatencyMs:     resp.LatencyMs,
		ShieldActive:  n.Runtime.Status().ShieldActive,
	}, nil
}

// splitCounter parses the model output into (revised_clause, rationale).
// The prompt asks for "1. revised clause body, 2. one-line rationale"
// so we look for a numbered split. Falls back to taking the last line
// as the rationale if numbering isn't present.
func splitCounter(raw string) (revised, rationale string) {
	if raw == "" {
		return "", ""
	}
	lower := strings.ToLower(raw)
	// Prefer explicit "2." rationale marker.
	if idx := strings.Index(lower, "\n2."); idx > 0 {
		revised = strings.TrimSpace(stripLeading(raw[:idx], "1."))
		rationale = strings.TrimSpace(stripLeading(raw[idx+1:], "2."))
		return
	}
	if idx := strings.Index(lower, "rationale:"); idx > 0 {
		revised = strings.TrimSpace(raw[:idx])
		rationale = strings.TrimSpace(raw[idx+len("rationale:"):])
		return
	}
	// Fall back: last non-empty line is the rationale.
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) <= 1 {
		return strings.TrimSpace(raw), ""
	}
	rationale = strings.TrimSpace(lines[len(lines)-1])
	revised = strings.TrimSpace(strings.Join(lines[:len(lines)-1], "\n"))
	return
}

func stripLeading(s, prefix string) string {
	t := strings.TrimSpace(s)
	t = strings.TrimPrefix(t, prefix)
	return strings.TrimSpace(t)
}
