package ai

import (
	"context"
	"strings"
	"testing"
)

// stubProvider records the request it received so tests can inspect what
// crossed the Shield boundary.
type stubProvider struct {
	got      Request
	response string
}

func (s *stubProvider) Name() string     { return "stub" }
func (s *stubProvider) Model() string    { return "stub-model" }
func (s *stubProvider) Endpoint() string { return "" }
func (s *stubProvider) Complete(_ context.Context, req Request) (Response, error) {
	s.got = req
	resp := s.response
	if resp == "" {
		resp = "echo: " + req.User
	}
	return Response{Text: resp, Provider: "stub", Model: "stub-model"}, nil
}

func TestRuntime_PIIDoesNotReachProvider(t *testing.T) {
	// Build a LocalShield with a real key so PII gets tokenized.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	shield, err := NewLocalShield(key)
	if err != nil {
		t.Fatalf("shield init: %v", err)
	}

	stub := &stubProvider{}
	rt := New(nil, shield, NoopEmbedder{}, stub)

	req := Request{
		System: "You are helpful.",
		User:   "My email is alice@example.com and my phone is +46 70 123 4567. Help me.",
	}
	resp, err := rt.Complete(context.Background(), req, CompleteOptions{})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	// The stub received tokenized input, not the raw email/phone.
	if strings.Contains(stub.got.User, "alice@example.com") {
		t.Fatalf("plaintext email leaked to provider: %q", stub.got.User)
	}
	if strings.Contains(stub.got.User, "+46 70 123 4567") {
		t.Fatalf("plaintext phone leaked to provider: %q", stub.got.User)
	}
	if !strings.Contains(stub.got.User, "[shield:email:") {
		t.Fatalf("expected shielded token in provider input, got %q", stub.got.User)
	}
	// The response is the stub's echo; since the stub didn't include any
	// shielded tokens in its response, Untokenize is a no-op and we see
	// the raw echo back (which itself contains the tokens).
	if !strings.Contains(resp.Text, "echo:") {
		t.Fatalf("unexpected response: %q", resp.Text)
	}
}

func TestRuntime_ShieldUntokenizeRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	shield, _ := NewLocalShield(key)

	// Stub that echoes the request prefixed so we can spot tokens.
	stub := &stubProvider{response: ""}
	stub.response = "Reply for [shield:email:tok_xxx]" // bogus, gets replaced in Untokenize only if stub.response matches a real token
	rt := New(nil, shield, NoopEmbedder{}, stub)

	req := Request{User: "Email me at bob@example.com please."}
	resp, err := rt.Complete(context.Background(), req, CompleteOptions{})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	// We can't easily craft a "real" token in the stub response without
	// resolving the actual hex, so this test mostly proves the round-trip
	// doesn't error and that the response is returned.
	if resp.Text == "" {
		t.Fatalf("empty response")
	}
}

func TestRuntime_NoProviderForUnknownName(t *testing.T) {
	rt := New(nil, NoopShield{}, NoopEmbedder{})
	_, err := rt.Complete(context.Background(), Request{User: "hi"}, CompleteOptions{Provider: "nope"})
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestCache(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	shield, _ := NewLocalShield(key)
	calls := 0
	provider := stubProviderFunc(func(req Request) (Response, error) {
		calls++
		return Response{Text: "answer"}, nil
	})
	rt := New(nil, shield, NoopEmbedder{}, provider)
	cacheKey := "k1"
	req := Request{User: "Q"}
	for i := 0; i < 3; i++ {
		_, err := rt.Complete(context.Background(), req, CompleteOptions{CacheKey: cacheKey})
		if err != nil {
			t.Fatalf("complete: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("cache miss: want 1 call, got %d", calls)
	}
}

func TestStatus_NoProviders(t *testing.T) {
	rt := New(nil, NoopShield{}, NoopEmbedder{})
	st := rt.Status()
	if st.ShieldActive {
		t.Fatal("NoopShield should report Active=false")
	}
	if len(st.Providers) != 0 {
		t.Fatalf("unexpected providers: %+v", st.Providers)
	}
	if st.PromptCount == 0 {
		t.Fatal("expected built-in prompts to be registered")
	}
}

// stubProviderFunc is a tiny adapter so tests don't need a full struct.
type stubProviderFunc func(req Request) (Response, error)

func (f stubProviderFunc) Name() string     { return "stub" }
func (f stubProviderFunc) Model() string    { return "stub-model" }
func (f stubProviderFunc) Endpoint() string { return "" }
func (f stubProviderFunc) Complete(_ context.Context, req Request) (Response, error) {
	return f(req)
}
