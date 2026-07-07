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
)

// MistralProvider talks to Mistral Large via the OpenRouter EU endpoint.
// Default URL points at OpenRouter's chat completions API; the model is
// configurable so a self-hosted Llama 3 70B can plug in with the same
// shape later.
type MistralProvider struct {
	BaseURL string // default "https://openrouter.ai/api/v1/chat/completions"
	APIKey  string // OpenRouter or self-hosted bearer
	ModelID string // e.g. "mistralai/mistral-large-latest"
	Client  HTTPDoer
}

// HTTPDoer is the minimal http.Client interface, swappable in tests.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// NewMistralProvider builds a provider. APIKey empty disables it: the
// runtime can still register the provider (so Status() shows it) but
// Complete returns an error pointing at the missing key.
func NewMistralProvider(baseURL, apiKey, model string) *MistralProvider {
	if baseURL == "" {
		baseURL = "https://openrouter.ai/api/v1/chat/completions"
	}
	if model == "" {
		model = "mistralai/mistral-large-latest"
	}
	return &MistralProvider{
		BaseURL: baseURL,
		APIKey:  apiKey,
		ModelID: model,
		Client:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (m *MistralProvider) Name() string     { return "mistral" }
func (m *MistralProvider) Model() string    { return m.ModelID }
func (m *MistralProvider) Endpoint() string { return m.BaseURL }

// chatRequest mirrors the OpenAI/OpenRouter chat completions shape.
type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature,omitempty"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Model string `json:"model"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (m *MistralProvider) Complete(ctx context.Context, req Request) (Response, error) {
	if m.APIKey == "" {
		return Response{}, errors.New("mistral: API key not configured")
	}
	msgs := []chatMessage{}
	if req.System != "" {
		msgs = append(msgs, chatMessage{Role: "system", Content: req.System})
	}
	msgs = append(msgs, chatMessage{Role: "user", Content: req.User})

	body, err := json.Marshal(chatRequest{
		Model:       m.ModelID,
		Messages:    msgs,
		Temperature: req.Temperature,
		MaxTokens:   req.MaxTokens,
	})
	if err != nil {
		return Response{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", m.BaseURL, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+m.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := m.Client.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("mistral request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return Response{}, err
	}
	if resp.StatusCode >= 400 {
		return Response{}, fmt.Errorf("mistral %d: %s", resp.StatusCode, string(raw))
	}
	var parsed chatResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return Response{}, fmt.Errorf("mistral decode: %w", err)
	}
	if parsed.Error != nil {
		return Response{}, fmt.Errorf("mistral error: %s", parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 {
		return Response{}, errors.New("mistral: empty response")
	}
	return Response{
		Text:         parsed.Choices[0].Message.Content,
		InputTokens:  parsed.Usage.PromptTokens,
		OutputTokens: parsed.Usage.CompletionTokens,
		Model:        parsed.Model,
		Provider:     "mistral",
	}, nil
}
