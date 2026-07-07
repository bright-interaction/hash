package aiapps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/brightinteraction/hash/internal/ai"
	"github.com/brightinteraction/hash/internal/blocks"
)

// RiskAnalyzer reads a contract draft block-by-block and flags clauses
// with elevated risk to the sender. Output is a deterministic list of
// findings (block id + category + severity + summary + suggested
// rewrite hint) so callers can render the result as a sidebar or
// blocking gate before send.
//
// Built on the same Phase 8.4 ai.Runtime as the other aiapps so audit +
// Shield tokenization apply automatically. The prompt is
// `risk_analyzer` registered in internal/ai/prompts.go.
type RiskAnalyzer struct {
	Runtime *ai.Runtime
}

// AnalyzeInput is the per-call shape. The block tree is supplied
// pre-parsed so the handler controls how blocks are selected (skip
// signature placeholders, omit empty paragraphs, etc).
type AnalyzeInput struct {
	OrgID         uuid.UUID
	DocumentID    uuid.UUID
	UserID        *uuid.UUID
	Locale        string // 'sv-SE' default
	Blocks        []blocks.Block
	SenderContext string // free-form notes about the sender's redlines + industry
}

// Severity values returned by the model. Anything else is normalized to
// 'medium' so the UI never crashes on a model that hallucinates a fifth
// level.
const (
	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"
)

// Finding is one item in the risk report.
type Finding struct {
	BlockID    string `json:"block_id"`
	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Summary    string `json:"summary"`
	Suggestion string `json:"suggestion"`
}

// AnalyzeResult bundles the findings with audit metadata.
type AnalyzeResult struct {
	Findings     []Finding `json:"findings"`
	RawText      string    `json:"raw_text"`
	Provider     string    `json:"provider"`
	Model        string    `json:"model"`
	InputTokens  int       `json:"input_tokens"`
	OutputTokens int       `json:"output_tokens"`
	LatencyMs    int       `json:"latency_ms"`
	ShieldActive bool      `json:"shield_active"`
}

// Analyze renders the risk_analyzer prompt + runs it. The block list is
// serialized line-by-line as compact JSON so the model can quote a
// stable block_id back in its findings. Empty block list returns an
// empty (non-error) result so the caller can still surface "no findings".
func (a *RiskAnalyzer) Analyze(ctx context.Context, in AnalyzeInput) (AnalyzeResult, error) {
	if a == nil || a.Runtime == nil {
		return AnalyzeResult{}, errors.New("risk_analyzer: AI runtime not configured")
	}
	if len(in.Blocks) == 0 {
		return AnalyzeResult{Findings: []Finding{}}, nil
	}
	locale := in.Locale
	if locale == "" {
		locale = "sv-SE"
	}
	prompt, err := a.Runtime.PromptReg.Get("risk_analyzer", 0)
	if err != nil {
		return AnalyzeResult{}, fmt.Errorf("risk_analyzer: prompt: %w", err)
	}
	encoded, err := encodeBlocksForRisk(in.Blocks)
	if err != nil {
		return AnalyzeResult{}, fmt.Errorf("encode blocks: %w", err)
	}
	req, err := prompt.Render(map[string]string{
		"Locale":        locale,
		"BlocksJSON":    encoded,
		"SenderContext": strOrDefault(in.SenderContext, "(none)"),
	})
	if err != nil {
		return AnalyzeResult{}, err
	}
	resp, err := a.Runtime.Complete(ctx, req, ai.CompleteOptions{
		OrgID:      in.OrgID,
		DocumentID: &in.DocumentID,
		UserID:     in.UserID,
		CacheKey:   ai.CacheKey(req),
	})
	if err != nil {
		return AnalyzeResult{}, err
	}
	out := AnalyzeResult{
		RawText:      resp.Text,
		Provider:     resp.Provider,
		Model:        resp.Model,
		InputTokens:  resp.InputTokens,
		OutputTokens: resp.OutputTokens,
		LatencyMs:    resp.LatencyMs,
		ShieldActive: a.Runtime.Status().ShieldActive,
		Findings:     []Finding{},
	}
	findings, perr := parseRiskFindings(resp.Text)
	if perr != nil {
		// Don't error on parse failures; surface as a single
		// `parse_error` finding so the UI shows it instead of a 500.
		out.Findings = []Finding{{
			Category: "other",
			Severity: SeverityMedium,
			Summary:  "parse_error: " + perr.Error(),
		}}
		return out, nil
	}
	out.Findings = normalizeFindings(findings)
	return out, nil
}

// encodeBlocksForRisk renders the block tree as a newline-delimited
// JSON stream so the model can refer back to block_id reliably. Each
// line is `{"id":"<id>","text":"<rendered>"}`; signature placeholders
// and empty bodies are dropped (no risk to analyse).
func encodeBlocksForRisk(bs []blocks.Block) (string, error) {
	var sb strings.Builder
	for i := range bs {
		b := bs[i]
		switch b.Type {
		case blocks.TypeSignatureField, blocks.TypeInitialField,
			blocks.TypeTextField, blocks.TypeDateField, blocks.TypeCheckbox,
			blocks.TypePageBreak, blocks.TypeDivider, blocks.TypeImage:
			continue
		}
		text := strings.TrimSpace(b.Text)
		if text == "" {
			continue
		}
		enc, err := json.Marshal(map[string]string{
			"id":   b.ID,
			"text": text,
		})
		if err != nil {
			return "", err
		}
		sb.Write(enc)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

type riskWire struct {
	Findings []Finding `json:"findings"`
}

// parseRiskFindings extracts the JSON envelope from the model's output.
// Accepts leading/trailing prose around the JSON object since some
// providers prepend "Here are the findings:" despite the prompt
// telling them not to.
func parseRiskFindings(raw string) ([]Finding, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("empty response")
	}
	start := strings.Index(trimmed, "{")
	end := strings.LastIndex(trimmed, "}")
	if start < 0 || end <= start {
		return nil, errors.New("no JSON object found")
	}
	var out riskWire
	if err := json.Unmarshal([]byte(trimmed[start:end+1]), &out); err != nil {
		return nil, err
	}
	return out.Findings, nil
}

// normalizeFindings clamps severity values to the known set, drops
// blank summaries, and orders by severity descending so the UI can
// render high-risk items first without re-sorting.
func normalizeFindings(in []Finding) []Finding {
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		summary := strings.TrimSpace(f.Summary)
		if summary == "" {
			continue
		}
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		switch sev {
		case SeverityLow, SeverityMedium, SeverityHigh:
		default:
			sev = SeverityMedium
		}
		cat := strings.TrimSpace(strings.ToLower(f.Category))
		if cat == "" {
			cat = "other"
		}
		out = append(out, Finding{
			BlockID:    strings.TrimSpace(f.BlockID),
			Category:   cat,
			Severity:   sev,
			Summary:    summary,
			Suggestion: strings.TrimSpace(f.Suggestion),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return severityRank(out[i].Severity) > severityRank(out[j].Severity)
	})
	return out
}

func severityRank(s string) int {
	switch s {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}
