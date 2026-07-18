// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package aiapps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/brightinteraction/hash/internal/ai"
)

// Bilingual runs Phase 11.3 semantic-equivalence checks across two
// clauses in different languages. The output is a JSON object
// `{equivalent, drift, confidence}` mirroring what the registered
// bilingual_equivalence prompt produces. Cross-border deals + Swedish
// contracts with English mirror translations are the primary callers.
type Bilingual struct {
	Runtime *ai.Runtime
}

// EquivalenceInput pairs two clauses, naming the language each is in.
// LangA/LangB are RFC 5646 tags (e.g. "sv-SE", "en-GB").
type EquivalenceInput struct {
	OrgID      uuid.UUID
	DocumentID uuid.UUID
	UserID     *uuid.UUID
	LangA      string
	ClauseA    string
	LangB      string
	ClauseB    string
}

// EquivalenceResult is the parsed JSON the model returns + provenance.
type EquivalenceResult struct {
	Equivalent   bool    `json:"equivalent"`
	Drift        string  `json:"drift"`
	Confidence   float64 `json:"confidence"`
	RawText      string  `json:"raw_text"`
	Provider     string  `json:"provider"`
	Model        string  `json:"model"`
	LatencyMs    int     `json:"latency_ms"`
	ShieldActive bool    `json:"shield_active"`
}

// Check runs the bilingual_equivalence prompt + parses the model's
// JSON. If the model returns malformed JSON (rare since the prompt is
// strict about output format), we return RawText with Equivalent=false
// and the parse error in Drift so the caller can surface it.
func (b *Bilingual) Check(ctx context.Context, in EquivalenceInput) (EquivalenceResult, error) {
	if b == nil || b.Runtime == nil {
		return EquivalenceResult{}, errors.New("bilingual: AI runtime not configured")
	}
	if in.ClauseA == "" || in.ClauseB == "" {
		return EquivalenceResult{}, errors.New("bilingual: both clause_a and clause_b required")
	}
	prompt, err := b.Runtime.PromptReg.Get("bilingual_equivalence", 0)
	if err != nil {
		return EquivalenceResult{}, fmt.Errorf("bilingual: prompt: %w", err)
	}
	req, err := prompt.Render(map[string]string{
		"LangA":   strOrDefault(in.LangA, "sv-SE"),
		"LangB":   strOrDefault(in.LangB, "en-GB"),
		"ClauseA": in.ClauseA,
		"ClauseB": in.ClauseB,
	})
	if err != nil {
		return EquivalenceResult{}, err
	}
	resp, err := b.Runtime.Complete(ctx, req, ai.CompleteOptions{
		OrgID:      in.OrgID,
		DocumentID: &in.DocumentID,
		UserID:     in.UserID,
		CacheKey:   ai.CacheKey(req),
	})
	if err != nil {
		return EquivalenceResult{}, err
	}
	out := EquivalenceResult{
		RawText:      resp.Text,
		Provider:     resp.Provider,
		Model:        resp.Model,
		LatencyMs:    resp.LatencyMs,
		ShieldActive: b.Runtime.Status().ShieldActive,
	}
	parsed, err := parseEquivalenceJSON(resp.Text)
	if err != nil {
		out.Drift = "parse_error: " + err.Error()
		return out, nil
	}
	out.Equivalent = parsed.Equivalent
	out.Drift = parsed.Drift
	out.Confidence = parsed.Confidence
	return out, nil
}

type equivalenceWire struct {
	Equivalent bool    `json:"equivalent"`
	Drift      string  `json:"drift"`
	Confidence float64 `json:"confidence"`
}

// parseEquivalenceJSON extracts the first JSON object from the model's
// reply. We allow leading/trailing prose so a slightly chatty model
// still parses.
func parseEquivalenceJSON(raw string) (equivalenceWire, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return equivalenceWire{}, errors.New("empty response")
	}
	start := strings.Index(trimmed, "{")
	end := strings.LastIndex(trimmed, "}")
	if start < 0 || end <= start {
		return equivalenceWire{}, errors.New("no JSON object found")
	}
	var out equivalenceWire
	if err := json.Unmarshal([]byte(trimmed[start:end+1]), &out); err != nil {
		return equivalenceWire{}, err
	}
	return out, nil
}

func strOrDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
