// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bright-interaction/hash/internal/nethard"
)

// AnthropicProvider talks to api.anthropic.com via the Messages API.
// Used for synthesis-heavy tasks where Anthropic's quality is worth the
// US-routing tradeoff. Shield-tokenization is mandatory in front of
// this provider so no PII reaches Anthropic infra.
type AnthropicProvider struct {
	BaseURL string // default https://api.anthropic.com/v1/messages
	APIKey  string
	ModelID string // e.g. "claude-sonnet-4-6" or "claude-opus-4-7"
	Version string // anthropic-version header
	Client  HTTPDoer
}

// NewAnthropicProvider builds a provider. allowPrivate=false (production) uses
// an SSRF-hardened transport that refuses to dial an internal/private IP, so a
// tenant BYOAI base_url cannot be rebound to reach cloud metadata or internal
// services at call time.
func NewAnthropicProvider(baseURL, apiKey, model string, allowPrivate bool) *AnthropicProvider {
	if baseURL == "" {
		baseURL = "https://api.anthropic.com/v1/messages"
	}
	if model == "" {
		model = "claude-sonnet-4-6"
	}
	return &AnthropicProvider{
		BaseURL: baseURL,
		APIKey:  apiKey,
		ModelID: model,
		Version: "2023-06-01",
		Client:  nethard.Client(30*time.Second, func() bool { return allowPrivate }),
	}
}

func (a *AnthropicProvider) Name() string     { return "anthropic" }
func (a *AnthropicProvider) Model() string    { return a.ModelID }
func (a *AnthropicProvider) Endpoint() string { return a.BaseURL }

type anthropicRequest struct {
	Model       string             `json:"model"`
	System      string             `json:"system,omitempty"`
	Messages    []anthropicMessage `json:"messages"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Model string `json:"model"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (a *AnthropicProvider) Complete(ctx context.Context, req Request) (Response, error) {
	if a.APIKey == "" {
		return Response{}, errors.New("anthropic: API key not configured")
	}
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 1024 // Anthropic requires a value
	}
	body, err := json.Marshal(anthropicRequest{
		Model:       a.ModelID,
		System:      req.System,
		Messages:    []anthropicMessage{{Role: "user", Content: req.User}},
		MaxTokens:   maxTokens,
		Temperature: req.Temperature,
	})
	if err != nil {
		return Response{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", a.BaseURL, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("x-api-key", a.APIKey)
	httpReq.Header.Set("anthropic-version", a.Version)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.Client.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("anthropic request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return Response{}, err
	}
	if resp.StatusCode >= 400 {
		return Response{}, fmt.Errorf("anthropic %d: %s", resp.StatusCode, string(raw))
	}
	var parsed anthropicResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return Response{}, fmt.Errorf("anthropic decode: %w", err)
	}
	if parsed.Error != nil {
		return Response{}, fmt.Errorf("anthropic error: %s", parsed.Error.Message)
	}
	if len(parsed.Content) == 0 {
		return Response{}, errors.New("anthropic: empty response")
	}
	out := ""
	for _, c := range parsed.Content {
		if c.Type == "text" {
			out += c.Text
		}
	}
	return Response{
		Text:         out,
		InputTokens:  parsed.Usage.InputTokens,
		OutputTokens: parsed.Usage.OutputTokens,
		Model:        parsed.Model,
		Provider:     "anthropic",
	}, nil
}
