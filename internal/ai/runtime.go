// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package ai is the Phase 8.4 foundation: a single layer in front of every
// LLM call Hash makes. Building per-feature LLM clients would mean
// wiring Shield three times, three retry policies, three prompt registries.
// One runtime keeps it sane.
//
// Provider selection rule (config-driven, defaults baked in):
//
//	PII-heavy tasks (signer clarifier, document content):
//	  EU-hosted Mistral via OpenRouter EU, OR self-hosted Llama 3 70B on
//	  a Hetzner GPU box later. PII is tokenized through Shield before
//	  crossing the network.
//
//	Synthesis-heavy tasks (negotiation suggestions over public clauses,
//	  bilingual checks on already-tokenized text):
//	  Anthropic via Shield (US infra, but the agent never sees PII).
//
//	Embeddings (RAG over doc + variables):
//	  BGE-M3 self-hosted (CPU is fine at our scale). Stub embedder
//	  ships in 8.4 so the runtime is wired; the real one lands when
//	  Phase 11.1 clarifier needs RAG.
//
// Every Complete + Embed call writes an ai_completion_audit row so
// reviewers can confirm shield_active was true for PII flows.
package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/db/generated"
)

// Provider is the per-vendor surface. Implementations live in
// provider_*.go and never depend on Hash-specific tables; they
// translate `Request` → vendor API → `Response` and that's it. The
// Runtime is what knits them together with Shield + cache + audit.
type Provider interface {
	Name() string
	Model() string
	// Endpoint returns the canonical HTTPS URL the provider sends to.
	// Used by the audit log to derive the transfer_jurisdiction tag so
	// EU-vs-non-EU shipping is queryable rather than inferred. Return
	// the empty string when the call stays local (NoopProvider).
	Endpoint() string
	Complete(ctx context.Context, req Request) (Response, error)
}

// Request is what callers pass to Runtime.Complete.
type Request struct {
	// System prompt; rendered into the provider's "system" slot.
	System string
	// User prompt (the most-recent turn). Multi-turn conversations
	// are out of scope for 8.4; if you need them, render history into
	// System or into a single User block.
	User string
	// MaxTokens caps the output. 0 means provider default.
	MaxTokens int
	// Temperature; 0 is deterministic for most providers.
	Temperature float64
	// PromptName + Version map this call to a registered prompt; the
	// audit row carries both so we can spot drift between prompt
	// versions and quality regressions.
	PromptName    string
	PromptVersion int
}

// Response captures the provider's reply + usage metadata.
type Response struct {
	Text         string
	InputTokens  int
	OutputTokens int
	Model        string
	Provider     string
	LatencyMs    int
}

// Shield is the LLM-boundary tokenizer. The runtime calls Shield(req)
// before crossing to a provider and Unshield(resp) on the way back.
// Implementations live in shield.go; a NoopShield is provided for
// dev/test environments without a configured key.
type Shield interface {
	// Active reports whether tokenization is actually configured. The
	// audit log captures this so reviewers can spot "shield disabled
	// in prod" mistakes.
	Active() bool
	// Tokenize replaces PII spans in the input with stable tokens.
	// Returns the tokenized text + a handle the response unshielder
	// uses to put plaintext back. knownTerms are caller-supplied literal
	// PII strings (e.g. the document's party names) redacted in addition
	// to the pattern-detected spans, so unstructured PII that no regex can
	// catch still never reaches the provider.
	Tokenize(ctx context.Context, in string, knownTerms ...string) (out string, handle Handle, err error)
	// Untokenize swaps tokens in the response back to their plaintext
	// values using the handle returned by Tokenize.
	Untokenize(ctx context.Context, in string, h Handle) (string, error)
}

// Handle is opaque to the runtime; each Shield implementation stores
// whatever it needs (token table, session reference, etc).
type Handle any

// Runtime is the single entry point for AI calls. Hold one process-wide.
type Runtime struct {
	Q         *generated.Queries
	Shield    Shield
	Cache     *Cache
	Providers map[string]Provider // keyed by Provider.Name(), e.g. "mistral"
	Default   string              // provider name to use when caller doesn't specify
	Embedder  Embedder            // see embedder.go
	PromptReg *PromptRegistry

	// ResolveOrgProvider, when non-nil, lets an org bring its own AI
	// provider + key (BYOAI). It returns (provider, true) when the org has
	// an enabled override, or (nil, false) to fall through to the instance
	// default. It is consulted only when the caller did not pin a specific
	// provider via CompleteOptions.Provider, so a nil resolver leaves the
	// existing instance-global behaviour exactly unchanged.
	ResolveOrgProvider func(ctx context.Context, orgID uuid.UUID) (Provider, bool)
}

// New builds a Runtime. Providers slice may be empty (a Runtime with no
// providers is still useful for unit tests + config-status reads); the
// first entry becomes the default unless explicitly overridden later.
func New(q *generated.Queries, shield Shield, embedder Embedder, providers ...Provider) *Runtime {
	if shield == nil {
		shield = NoopShield{}
	}
	if embedder == nil {
		embedder = NoopEmbedder{}
	}
	m := map[string]Provider{}
	var def string
	for _, p := range providers {
		m[p.Name()] = p
		if def == "" {
			def = p.Name()
		}
	}
	return &Runtime{
		Q:         q,
		Shield:    shield,
		Cache:     NewCache(15 * time.Minute),
		Providers: m,
		Default:   def,
		Embedder:  embedder,
		PromptReg: NewPromptRegistry(),
	}
}

// Status describes the runtime's configuration for ai_runtime_status
// reads. No usage data, no PII; safe to expose to operators.
type Status struct {
	ShieldActive bool     `json:"shield_active"`
	Providers    []string `json:"providers"`
	Default      string   `json:"default"`
	Embedder     string   `json:"embedder"`
	PromptCount  int      `json:"prompt_count"`
}

// Status reports the runtime's current configuration.
func (r *Runtime) Status() Status {
	out := Status{
		ShieldActive: r.Shield.Active(),
		Default:      r.Default,
		Embedder:     r.Embedder.Name(),
		PromptCount:  r.PromptReg.Count(),
		Providers:    make([]string, 0, len(r.Providers)),
	}
	for name := range r.Providers {
		out.Providers = append(out.Providers, name)
	}
	return out
}

// Complete runs req through Shield → cache → provider → Untokenize, and
// writes an ai_completion_audit row. Callers supply orgID/docID/userID
// for the audit attribution; pass nil for ad-hoc calls outside a
// document context (none in 8.4, but Phase 11+ tools may need it).
type CompleteOptions struct {
	OrgID      uuid.UUID
	DocumentID *uuid.UUID
	UserID     *uuid.UUID
	Provider   string // overrides r.Default; empty = use default
	// CacheKey, if set, dedupes identical requests across this process.
	// Leave empty to skip caching.
	CacheKey string
	// KnownPII are extra literal strings to redact before the provider call
	// (on top of pattern detection + the document's party names, which the
	// runtime gathers automatically when DocumentID is set).
	KnownPII []string
}

func (r *Runtime) Complete(ctx context.Context, req Request, opts CompleteOptions) (Response, error) {
	providerName := opts.Provider
	var provider Provider
	var ok bool
	// Per-org BYOAI override: only when the caller did not pin a provider.
	if providerName == "" && r.ResolveOrgProvider != nil && opts.OrgID != uuid.Nil {
		if p, has := r.ResolveOrgProvider(ctx, opts.OrgID); has {
			provider, ok = p, true
		}
	}
	if !ok {
		if providerName == "" {
			providerName = r.Default
		}
		provider, ok = r.Providers[providerName]
		if !ok {
			return Response{}, fmt.Errorf("ai runtime: provider %q not registered", providerName)
		}
	}

	// Cache lookup first; the cache key already incorporates the prompt
	// text so cached entries are safe to re-serve.
	if opts.CacheKey != "" {
		if hit, ok := r.Cache.get(opts.CacheKey); ok {
			return hit, nil
		}
	}

	// Gather the document's party names so Shield redacts them too: no regex
	// catches a free-text personal name, but the recipients table knows them.
	//
	// KNOWN COVERAGE LIMIT (audit L2): structured PII (email/IBAN/personnummer/
	// phone) in free text IS tokenized, and recipient names are added below, but a
	// person named ONLY in clause text (e.g. a guarantor who is not a recipient)
	// matches no regex and is not in the recipients table, so it can reach the
	// provider untokenized. This is a defense-in-depth/marketing-accuracy gap, NOT
	// a residency breach: both the instance-default and BYOAI provider paths are
	// EU-endpoint-locked (config.validateAIEUConfig + ai_provider validateBYOAIBaseURL),
	// so the text only reaches an EU-hosted processor. Callers can pass extra
	// non-recipient party names via opts.KnownPII; closing the gap fully needs an
	// NER/address pass, deferred.
	known := append([]string{}, opts.KnownPII...)
	if opts.DocumentID != nil && r.Q != nil {
		if recs, rerr := r.Q.ListRecipientsByDocument(ctx, *opts.DocumentID); rerr == nil {
			for _, rec := range recs {
				if rec != nil && strings.TrimSpace(rec.Name) != "" {
					known = append(known, rec.Name)
				}
			}
		}
	}

	// Shield outbound. Both system and user blocks are tokenized; we
	// re-stitch with the same handle so Untokenize works.
	shieldedUser, handle, err := r.Shield.Tokenize(ctx, req.User, known...)
	if err != nil {
		r.writeAudit(ctx, opts, provider, req, Response{}, 0, false, err)
		return Response{}, fmt.Errorf("shield tokenize: %w", err)
	}
	shieldedSystem, _, err := r.Shield.Tokenize(ctx, req.System, known...)
	if err != nil {
		r.writeAudit(ctx, opts, provider, req, Response{}, 0, false, err)
		return Response{}, fmt.Errorf("shield tokenize system: %w", err)
	}
	out := req
	out.User = shieldedUser
	out.System = shieldedSystem

	start := time.Now()
	resp, err := provider.Complete(ctx, out)
	latency := int(time.Since(start) / time.Millisecond)
	if err != nil {
		r.writeAudit(ctx, opts, provider, req, resp, latency, false, err)
		return Response{}, err
	}
	resp.LatencyMs = latency

	// Shield inbound.
	plain, err := r.Shield.Untokenize(ctx, resp.Text, handle)
	if err != nil {
		r.writeAudit(ctx, opts, provider, req, resp, latency, false, err)
		return Response{}, fmt.Errorf("shield untokenize: %w", err)
	}
	resp.Text = plain

	if opts.CacheKey != "" {
		r.Cache.put(opts.CacheKey, resp)
	}
	r.writeAudit(ctx, opts, provider, req, resp, latency, true, nil)
	return resp, nil
}

// CacheKey is a helper for callers; SHA-256 over the system+user+prompt
// keying so identical inputs collapse on the cache.
func CacheKey(req Request) string {
	h := sha256.New()
	h.Write([]byte(req.System))
	h.Write([]byte{0})
	h.Write([]byte(req.User))
	h.Write([]byte{0})
	h.Write([]byte(req.PromptName))
	return hex.EncodeToString(h.Sum(nil))
}

func (r *Runtime) writeAudit(ctx context.Context, opts CompleteOptions, p Provider, req Request, resp Response, latency int, success bool, err error) {
	if r.Q == nil {
		return // tests may run without DB
	}
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	var docID, userID pgtype.UUID
	if opts.DocumentID != nil {
		docID = pgtype.UUID{Bytes: *opts.DocumentID, Valid: true}
	}
	if opts.UserID != nil {
		userID = pgtype.UUID{Bytes: *opts.UserID, Valid: true}
	}
	// Best-effort log; never fail the call because of audit table issues.
	_, _ = r.Q.InsertAICompletionAudit(ctx, generated.InsertAICompletionAuditParams{
		OrgID:                opts.OrgID,
		DocumentID:           docID,
		ActorUserID:          userID,
		Provider:             p.Name(),
		Model:                p.Model(),
		PromptName:           req.PromptName,
		PromptVersion:        int32(req.PromptVersion),
		ShieldActive:         r.Shield.Active(),
		InputTokens:          int32(resp.InputTokens),
		OutputTokens:         int32(resp.OutputTokens),
		LatencyMs:            int32(latency),
		Success:              success,
		Error:                errStr,
		TransferJurisdiction: TransferJurisdictionForEndpoint(p.Endpoint()),
	})
}

// TransferJurisdictionForEndpoint returns the canonical jurisdiction tag
// for a provider endpoint URL. Pure function so tests + the dashboard
// can share it.
func TransferJurisdictionForEndpoint(endpoint string) string {
	if endpoint == "" {
		return "local"
	}
	low := strings.ToLower(strings.TrimSpace(endpoint))
	u, err := url.Parse(low)
	host := ""
	if err == nil {
		host = u.Hostname()
	}
	if host == "" {
		// Endpoint not parseable; tag explicitly so an auditor can
		// grep for misconfig without losing the row.
		return "unknown"
	}
	switch {
	case host == "api.mistral.ai", strings.HasSuffix(host, ".mistral.ai"),
		host == "eu.anthropic.com", strings.HasSuffix(host, ".eu.anthropic.com"),
		host == "eu.openrouter.ai", host == "eu.api.openrouter.ai",
		strings.Contains(host, ".eu."), strings.HasSuffix(host, ".eu"):
		return "EU->EU"
	case host == "api.anthropic.com", host == "api.openai.com", host == "openrouter.ai":
		return "EU->US"
	default:
		return "EU->OTHER"
	}
}

// Embedder is the embeddings surface. RAG features (Phase 11.1 clarifier)
// will call Embed for the candidate clauses + the user query, then do
// cosine similarity in app code (until we add pgvector).
type Embedder interface {
	Name() string
	Dimensions() int
	Embed(ctx context.Context, texts []string) ([][]float32, error)
}

// MarshalEmbedding is a small helper for callers persisting embeddings;
// keeps the storage shape (JSONB array of floats) in one place.
func MarshalEmbedding(vec []float32) (json.RawMessage, error) {
	return json.Marshal(vec)
}

// Cache is a thin process-wide LRU keyed by SHA-256 of the request.
type Cache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]cacheEntry
}

type cacheEntry struct {
	resp Response
	at   time.Time
}

func NewCache(ttl time.Duration) *Cache {
	return &Cache{ttl: ttl, m: map[string]cacheEntry{}}
}

func (c *Cache) get(key string) (Response, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return Response{}, false
	}
	if time.Since(e.at) > c.ttl {
		delete(c.m, key)
		return Response{}, false
	}
	return e.resp, true
}

func (c *Cache) put(key string, r Response) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = cacheEntry{resp: r, at: time.Now()}
}

// ErrNoProvider is returned by Complete when no provider matches.
var ErrNoProvider = errors.New("no AI provider configured")
