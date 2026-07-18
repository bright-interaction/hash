// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package aiapps wraps the Phase 8.4 ai.Runtime into three thin
// application-level helpers Phase 11 needs: the signer clarifier, the
// negotiation counter-suggester, and the bilingual equivalence
// checker. Keeping these in one package (rather than three) means each
// feature reuses the same audit + Shield-tokenized path and the test
// surface stays consolidated.
package aiapps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/brightinteraction/hash/internal/ai"
)

// Clarifier produces a plain-language explanation of a contract clause
// for a signer. RAG-grounded: callers supply surrounding clauses + any
// legal-context references they want the model to lean on.
type Clarifier struct {
	Runtime *ai.Runtime
}

// ClarifyInput is what the signer-side handler builds before calling
// the runtime. Locale shapes the response language (Swedish for sv-*,
// English otherwise; the prompt itself notes "translate jargon into
// everyday Swedish or English to match the signer's locale").
type ClarifyInput struct {
	OrgID              uuid.UUID
	DocumentID         uuid.UUID
	UserID             *uuid.UUID // sender if known, nil for signer-side calls
	Locale             string     // 'sv-SE', 'en-GB', etc; empty defaults to 'sv-SE'
	ClauseText         string
	SurroundingContext string
	LegalContext       string
	Question           string // empty means "explain this"
}

// ClarifyResult bundles the answer with the audit metadata.
type ClarifyResult struct {
	Answer       string `json:"answer"`
	Provider     string `json:"provider"`
	Model        string `json:"model"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
	LatencyMs    int    `json:"latency_ms"`
	ShieldActive bool   `json:"shield_active"`
}

// Clarify renders the registered signer_clarifier prompt and runs it
// through the runtime. Locale falls back to Swedish (the primary
// audience). Empty ClauseText is an error since there's nothing to
// explain.
func (c *Clarifier) Clarify(ctx context.Context, in ClarifyInput) (ClarifyResult, error) {
	if c == nil || c.Runtime == nil {
		return ClarifyResult{}, errors.New("clarifier: AI runtime not configured")
	}
	if in.ClauseText == "" {
		return ClarifyResult{}, errors.New("clarifier: clause_text required")
	}
	locale := in.Locale
	if locale == "" {
		locale = "sv-SE"
	}
	prompt, err := c.Runtime.PromptReg.Get("signer_clarifier", 0)
	if err != nil {
		return ClarifyResult{}, fmt.Errorf("clarifier: prompt: %w", err)
	}
	req, err := prompt.Render(map[string]string{
		"Locale":             locale,
		"ClauseText":         in.ClauseText,
		"SurroundingContext": in.SurroundingContext,
		"LegalContext":       in.LegalContext,
		"Question":           in.Question,
	})
	if err != nil {
		return ClarifyResult{}, err
	}
	resp, err := c.Runtime.Complete(ctx, req, ai.CompleteOptions{
		OrgID:      in.OrgID,
		DocumentID: &in.DocumentID,
		UserID:     in.UserID,
		CacheKey:   ai.CacheKey(req),
	})
	if err != nil {
		return ClarifyResult{}, err
	}
	return ClarifyResult{
		Answer:       resp.Text,
		Provider:     resp.Provider,
		Model:        resp.Model,
		InputTokens:  resp.InputTokens,
		OutputTokens: resp.OutputTokens,
		LatencyMs:    resp.LatencyMs,
		ShieldActive: c.Runtime.Status().ShieldActive,
	}, nil
}

// guard against the encoding/json import being dropped if the package
// briefly looks empty.
var _ = json.Marshal
