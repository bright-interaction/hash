// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package aiapps

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/brightinteraction/hash/internal/ai"
	"github.com/brightinteraction/hash/internal/blocks"
)

// blocksBlockSlice + blocksBlock are aliases used in this file to keep
// the table-driven risk tests compact. Tests construct rows and call
// toBlocks() to get the real []blocks.Block.
type blocksBlock struct {
	ID, Type, Text string
}

type blocksBlockSlice []blocksBlock

func (s blocksBlockSlice) toBlocks() []blocks.Block {
	out := make([]blocks.Block, len(s))
	for i, b := range s {
		out[i] = blocks.Block{
			ID:   b.ID,
			Type: blocks.Type(b.Type),
			Text: b.Text,
		}
	}
	return out
}

// stub provider returns a fixed response so we can exercise the
// runtime+prompt path without standing up a real model server.
type stubProvider struct {
	response string
}

func (s *stubProvider) Name() string     { return "stub" }
func (s *stubProvider) Model() string    { return "stub-model" }
func (s *stubProvider) Endpoint() string { return "" }
func (s *stubProvider) Complete(_ context.Context, _ ai.Request) (ai.Response, error) {
	return ai.Response{Text: s.response, Provider: "stub", Model: "stub-model"}, nil
}

func mkRuntime(resp string) *ai.Runtime {
	return ai.New(nil, ai.NoopShield{}, ai.NoopEmbedder{}, &stubProvider{response: resp})
}

func TestClarifier_RequiresClauseText(t *testing.T) {
	c := &Clarifier{Runtime: mkRuntime("ok")}
	_, err := c.Clarify(context.Background(), ClarifyInput{DocumentID: uuid.New()})
	if err == nil || !strings.Contains(err.Error(), "clause_text") {
		t.Fatalf("expected clause_text error, got %v", err)
	}
}

func TestClarifier_HappyPath(t *testing.T) {
	c := &Clarifier{Runtime: mkRuntime("Avtalet säger att...")}
	res, err := c.Clarify(context.Background(), ClarifyInput{
		OrgID:      uuid.New(),
		DocumentID: uuid.New(),
		ClauseText: "Force majeure clause...",
	})
	if err != nil {
		t.Fatalf("clarify: %v", err)
	}
	if !strings.Contains(res.Answer, "Avtalet") {
		t.Fatalf("expected stub answer, got %q", res.Answer)
	}
	if res.Provider != "stub" {
		t.Errorf("provider should be stub, got %q", res.Provider)
	}
}

func TestClarifier_NilRuntimeErrors(t *testing.T) {
	var c *Clarifier
	_, err := c.Clarify(context.Background(), ClarifyInput{ClauseText: "x"})
	if err == nil {
		t.Fatal("nil clarifier should error")
	}
}

func TestNegotiator_HappyPathSplitsRationale(t *testing.T) {
	body := "1. Revised clause body that addresses the concern.\n2. Switched indemnification cap from 10x to 5x because the lower bound matches what closed in similar deals."
	n := &Negotiator{Runtime: mkRuntime(body)}
	res, err := n.SuggestCounter(context.Background(), CounterInput{
		OrgID:          uuid.New(),
		DocumentID:     uuid.New(),
		OriginalClause: "Indemnification cap of 10x...",
		Concern:        "Cap is unusually high",
	})
	if err != nil {
		t.Fatalf("suggest: %v", err)
	}
	if !strings.Contains(res.RevisedClause, "Revised clause body") {
		t.Errorf("revised clause off: %q", res.RevisedClause)
	}
	if !strings.Contains(res.Rationale, "10x to 5x") {
		t.Errorf("rationale off: %q", res.Rationale)
	}
}

func TestNegotiator_FallbackWhenNoSplit(t *testing.T) {
	n := &Negotiator{Runtime: mkRuntime("Revised text\nRationale: Because X.")}
	res, err := n.SuggestCounter(context.Background(), CounterInput{
		OrgID:          uuid.New(),
		DocumentID:     uuid.New(),
		OriginalClause: "x",
	})
	if err != nil {
		t.Fatalf("suggest: %v", err)
	}
	if !strings.Contains(res.Rationale, "Because X") {
		t.Errorf("rationale parse failed: %+v", res)
	}
}

func TestBilingual_ParseClean(t *testing.T) {
	resp := `{"equivalent": false, "drift": "EN omits the indemnification cap that's in SV", "confidence": 0.82}`
	b := &Bilingual{Runtime: mkRuntime(resp)}
	res, err := b.Check(context.Background(), EquivalenceInput{
		ClauseA: "SV clause", ClauseB: "EN clause", LangA: "sv-SE", LangB: "en-GB",
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if res.Equivalent {
		t.Errorf("equivalent should be false")
	}
	if !strings.Contains(res.Drift, "indemnification") {
		t.Errorf("drift parse off: %q", res.Drift)
	}
	if res.Confidence < 0.8 || res.Confidence > 0.9 {
		t.Errorf("confidence parse off: %v", res.Confidence)
	}
}

func TestBilingual_ParseEmbeddedInProse(t *testing.T) {
	resp := "Here's the analysis: {\"equivalent\": true, \"drift\": \"\", \"confidence\": 0.95} done."
	b := &Bilingual{Runtime: mkRuntime(resp)}
	res, err := b.Check(context.Background(), EquivalenceInput{ClauseA: "a", ClauseB: "b"})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !res.Equivalent {
		t.Errorf("equivalent should be true")
	}
}

func TestBilingual_MalformedSurfacesParseError(t *testing.T) {
	b := &Bilingual{Runtime: mkRuntime("not JSON")}
	res, err := b.Check(context.Background(), EquivalenceInput{ClauseA: "a", ClauseB: "b"})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !strings.HasPrefix(res.Drift, "parse_error") {
		t.Errorf("expected parse_error in drift, got %q", res.Drift)
	}
}

func TestBilingual_MissingClauseErrors(t *testing.T) {
	b := &Bilingual{Runtime: mkRuntime("{}")}
	_, err := b.Check(context.Background(), EquivalenceInput{ClauseA: "a"})
	if err == nil {
		t.Fatal("missing clause_b should error")
	}
}

func TestNegotiator_NilRuntime(t *testing.T) {
	var n *Negotiator
	_, err := n.SuggestCounter(context.Background(), CounterInput{OriginalClause: "x"})
	if err == nil || !errors.Is(err, err) { // guard for non-nil err
		// just ensure non-nil
	}
	if err == nil {
		t.Fatal("expected error on nil runtime")
	}
}

func TestRiskAnalyzer_EmptyBlocksReturnsEmpty(t *testing.T) {
	a := &RiskAnalyzer{Runtime: mkRuntime("{}")}
	res, err := a.Analyze(context.Background(), AnalyzeInput{
		OrgID: uuid.New(), DocumentID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(res.Findings))
	}
}

func TestRiskAnalyzer_NilRuntimeErrors(t *testing.T) {
	var a *RiskAnalyzer
	_, err := a.Analyze(context.Background(), AnalyzeInput{})
	if err == nil {
		t.Fatal("nil analyzer should error")
	}
}

func TestRiskAnalyzer_HappyPath(t *testing.T) {
	stub := `{"findings": [
		{"block_id": "b1", "category": "liability", "severity": "high", "summary": "Indemnification cap absent", "suggestion": "Add cap at 12 months fees"},
		{"block_id": "b2", "category": "auto_renewal", "severity": "medium", "summary": "Auto-renews without notice window", "suggestion": "Add 60-day notice"}
	]}`
	a := &RiskAnalyzer{Runtime: mkRuntime(stub)}
	res, err := a.Analyze(context.Background(), AnalyzeInput{
		OrgID:      uuid.New(),
		DocumentID: uuid.New(),
		Blocks: (blocksBlockSlice{
			{ID: "b1", Type: "paragraph", Text: "The Provider shall indemnify..."},
			{ID: "b2", Type: "paragraph", Text: "This agreement auto-renews..."},
		}).toBlocks(),
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(res.Findings))
	}
	// Highest severity first.
	if res.Findings[0].Severity != SeverityHigh {
		t.Errorf("expected high first, got %q", res.Findings[0].Severity)
	}
	if res.Findings[0].Category != "liability" {
		t.Errorf("category off: %q", res.Findings[0].Category)
	}
	if res.Findings[1].Severity != SeverityMedium {
		t.Errorf("expected medium second, got %q", res.Findings[1].Severity)
	}
}

func TestRiskAnalyzer_ParseErrorSurfacesAsFinding(t *testing.T) {
	a := &RiskAnalyzer{Runtime: mkRuntime("not JSON at all")}
	res, err := a.Analyze(context.Background(), AnalyzeInput{
		OrgID: uuid.New(), DocumentID: uuid.New(),
		Blocks: (blocksBlockSlice{{ID: "b1", Type: "paragraph", Text: "x"}}).toBlocks(),
	})
	if err != nil {
		t.Fatalf("analyze should not error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	if !strings.HasPrefix(res.Findings[0].Summary, "parse_error") {
		t.Errorf("expected parse_error summary, got %q", res.Findings[0].Summary)
	}
}

func TestRiskAnalyzer_NormalizesBadSeverity(t *testing.T) {
	stub := `{"findings": [
		{"block_id": "b1", "category": "other", "severity": "CATASTROPHIC", "summary": "Bad severity stub", "suggestion": ""}
	]}`
	a := &RiskAnalyzer{Runtime: mkRuntime(stub)}
	res, err := a.Analyze(context.Background(), AnalyzeInput{
		OrgID: uuid.New(), DocumentID: uuid.New(),
		Blocks: (blocksBlockSlice{{ID: "b1", Type: "paragraph", Text: "x"}}).toBlocks(),
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1, got %d", len(res.Findings))
	}
	if res.Findings[0].Severity != SeverityMedium {
		t.Errorf("expected medium fallback, got %q", res.Findings[0].Severity)
	}
}

func TestEncodeBlocksForRisk_SkipsSignaturePlaceholders(t *testing.T) {
	bs := (blocksBlockSlice{
		{ID: "b1", Type: "signature_field", Text: ""},
		{ID: "b2", Type: "paragraph", Text: "real clause body"},
		{ID: "b3", Type: "page_break", Text: ""},
		{ID: "b4", Type: "paragraph", Text: ""},
	}).toBlocks()
	got, err := encodeBlocksForRisk(bs)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.Contains(got, `"b2"`) {
		t.Errorf("expected b2 included, got %q", got)
	}
	if strings.Contains(got, `"b1"`) || strings.Contains(got, `"b3"`) || strings.Contains(got, `"b4"`) {
		t.Errorf("expected b1/b3/b4 skipped, got %q", got)
	}
}
