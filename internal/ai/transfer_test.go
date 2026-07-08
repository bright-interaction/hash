package ai

import "testing"

func TestTransferJurisdictionForEndpoint(t *testing.T) {
	cases := map[string]string{
		"": "local",
		"https://api.mistral.ai/v1/chat/completions": "EU->EU",
		"https://chat.api.mistral.ai/v1/c":           "EU->EU",
		"https://eu.anthropic.com/v1/messages":       "EU->EU",
		"https://eu.openrouter.ai/api/v1/chat":       "EU->EU",
		"https://llm.eu.brightinteraction.com/v1":    "EU->EU",
		"https://sovereign-llm.eu/v1":                "EU->EU",
		"https://api.anthropic.com/v1/messages":      "EU->US",
		"https://api.openai.com/v1/chat":             "EU->US",
		"https://openrouter.ai/api/v1/chat":          "EU->US",
		"https://api.example.com/v1":                 "EU->OTHER",
		"not-a-url":                                  "unknown",
	}
	for in, want := range cases {
		if got := TransferJurisdictionForEndpoint(in); got != want {
			t.Errorf("TransferJurisdictionForEndpoint(%q) = %q, want %q", in, got, want)
		}
	}
}
