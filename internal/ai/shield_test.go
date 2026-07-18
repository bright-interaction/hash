// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package ai

import (
	"context"
	"strings"
	"testing"
)

func TestLocalShield_TokenizeAndUntokenize(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sh, err := NewLocalShield(key)
	if err != nil {
		t.Fatalf("NewLocalShield: %v", err)
	}
	if !sh.Active() {
		t.Fatal("Active should be true with a configured key")
	}
	in := "Send to alice@example.com and call +46 70 555 1234."
	tok, handle, err := sh.Tokenize(context.Background(), in)
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}
	if strings.Contains(tok, "alice@example.com") {
		t.Fatalf("plaintext email leaked: %q", tok)
	}
	if strings.Contains(tok, "+46 70 555 1234") {
		t.Fatalf("plaintext phone leaked: %q", tok)
	}
	if !strings.Contains(tok, "[shield:email:") {
		t.Fatalf("expected email shield token, got %q", tok)
	}

	// Round-trip the tokens back to plaintext. The response in real use
	// would contain the same token strings the provider received.
	out, err := sh.Untokenize(context.Background(), tok, handle)
	if err != nil {
		t.Fatalf("Untokenize: %v", err)
	}
	if !strings.Contains(out, "alice@example.com") {
		t.Fatalf("untokenize failed to restore email: %q", out)
	}
	if !strings.Contains(out, "+46 70 555 1234") {
		t.Fatalf("untokenize failed to restore phone: %q", out)
	}
}

func TestLocalShield_DeterministicTokens(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sh, _ := NewLocalShield(key)
	a, _, _ := sh.Tokenize(context.Background(), "alice@example.com")
	b, _, _ := sh.Tokenize(context.Background(), "alice@example.com")
	if a != b {
		t.Fatalf("expected stable token across calls, got %q vs %q", a, b)
	}
}

func TestLocalShield_EmptyKeyFallsBackToNoop(t *testing.T) {
	sh, err := NewLocalShield(nil)
	if err != nil {
		t.Fatalf("nil key should not error: %v", err)
	}
	if sh.Active() {
		t.Fatal("empty key should yield NoopShield with Active=false")
	}
}

func TestLocalShield_BadKeyLength(t *testing.T) {
	_, err := NewLocalShield(make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestLocalShield_ShortPhoneNotTouched(t *testing.T) {
	key := make([]byte, 32)
	sh, _ := NewLocalShield(key)
	tok, _, _ := sh.Tokenize(context.Background(), "Year 2026 with code 555")
	if !strings.Contains(tok, "Year 2026 with code 555") {
		t.Fatalf("short numbers should not be tokenized, got %q", tok)
	}
}

func TestPromptRegistry_BuiltIns(t *testing.T) {
	reg := NewPromptRegistry()
	if reg.Count() < 3 {
		t.Fatalf("expected at least 3 built-in prompts, got %d", reg.Count())
	}
	for _, name := range []string{"signer_clarifier", "negotiation_counter", "bilingual_equivalence"} {
		p, err := reg.Get(name, 0)
		if err != nil {
			t.Fatalf("missing built-in %q: %v", name, err)
		}
		if p.Version < 1 {
			t.Fatalf("%q version should be >= 1", name)
		}
	}
}

func TestPromptRegistry_RenderClarifier(t *testing.T) {
	reg := NewPromptRegistry()
	p, _ := reg.Get("signer_clarifier", 0)
	req, err := p.Render(map[string]string{
		"Locale":             "sv-SE",
		"ClauseText":         "Avtalsbrott medför skadestånd.",
		"SurroundingContext": "Mellan parterna gäller följande.",
		"LegalContext":       "Avtalslagen § 36.",
		"Question":           "Vad betyder detta?",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if req.PromptName != "signer_clarifier" {
		t.Fatalf("missing prompt_name on rendered request")
	}
	if !strings.Contains(req.User, "Avtalsbrott") {
		t.Fatalf("clause text missing from rendered user prompt")
	}
}

func TestHashEmbedder_Stable(t *testing.T) {
	e := HashEmbedder{Dim: 32}
	a, _ := e.Embed(context.Background(), []string{"hello"})
	b, _ := e.Embed(context.Background(), []string{"hello"})
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected 1 vector each, got %d/%d", len(a), len(b))
	}
	if e.Dimensions() != 32 {
		t.Fatalf("dim wrong: %d", e.Dimensions())
	}
	for i := range a[0] {
		if a[0][i] != b[0][i] {
			t.Fatalf("embedding not stable at %d: %v vs %v", i, a[0][i], b[0][i])
		}
	}
}

func TestCosineSimilarity(t *testing.T) {
	a := []float32{1, 0, 0}
	b := []float32{1, 0, 0}
	if got := CosineSimilarity(a, b); got < 0.99 {
		t.Fatalf("identical vectors should be ~1, got %f", got)
	}
	c := []float32{0, 1, 0}
	if got := CosineSimilarity(a, c); got > 0.01 || got < -0.01 {
		t.Fatalf("orthogonal vectors should be ~0, got %f", got)
	}
	d := []float32{-1, 0, 0}
	if got := CosineSimilarity(a, d); got > -0.99 {
		t.Fatalf("opposite vectors should be ~-1, got %f", got)
	}
}

func TestLocalShield_LowercaseIBANTokenized(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sh, err := NewLocalShield(key)
	if err != nil {
		t.Fatalf("NewLocalShield: %v", err)
	}
	// A lowercase / mixed-case IBAN must still be tokenized before any text
	// reaches the LLM; the case-sensitive detector used to leak it.
	in := "Betala till se4550000000058398256789 senast fredag."
	tok, handle, err := sh.Tokenize(context.Background(), in)
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}
	if strings.Contains(tok, "se4550000000058398256789") {
		t.Fatalf("lowercase IBAN leaked to the model: %q", tok)
	}
	if !strings.Contains(tok, "[shield:iban:") {
		t.Fatalf("expected an iban shield token, got %q", tok)
	}
	out, err := sh.Untokenize(context.Background(), tok, handle)
	if err != nil {
		t.Fatalf("Untokenize: %v", err)
	}
	if !strings.Contains(out, "se4550000000058398256789") {
		t.Fatalf("untokenize failed to restore the IBAN: %q", out)
	}
}
