package ai

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"text/template"
)

// PromptRegistry is the versioned prompt store. Every registered prompt
// carries a name + integer version so the audit log can correlate output
// quality with prompt-version changes. No string literals in handlers:
// callers fetch by (name, version) and Render with their inputs.
//
// Reasonable default behaviour: Get(name, 0) returns the highest
// registered version, so a new prompt rev becomes the default once
// registered without code changes elsewhere.
type PromptRegistry struct {
	mu       sync.RWMutex
	versions map[string]map[int]*Prompt // name -> version -> Prompt
}

type Prompt struct {
	Name        string
	Version     int
	Description string
	SystemTpl   *template.Template
	UserTpl     *template.Template
	// MaxTokens hint for callers. Runtime.Request.MaxTokens overrides.
	MaxTokens int
}

func NewPromptRegistry() *PromptRegistry {
	r := &PromptRegistry{versions: map[string]map[int]*Prompt{}}
	registerBuiltinPrompts(r)
	return r
}

// Register adds a prompt at name+version. Both system and user are Go
// text/template strings; Render fills them with the input data.
func (r *PromptRegistry) Register(name string, version int, description, systemTmpl, userTmpl string, maxTokens int) error {
	if name == "" {
		return errors.New("prompt name required")
	}
	if version < 1 {
		return errors.New("prompt version must be >= 1")
	}
	sys, err := template.New(name + ".system").Parse(systemTmpl)
	if err != nil {
		return fmt.Errorf("system template: %w", err)
	}
	usr, err := template.New(name + ".user").Parse(userTmpl)
	if err != nil {
		return fmt.Errorf("user template: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.versions[name]; !ok {
		r.versions[name] = map[int]*Prompt{}
	}
	r.versions[name][version] = &Prompt{
		Name:        name,
		Version:     version,
		Description: description,
		SystemTpl:   sys,
		UserTpl:     usr,
		MaxTokens:   maxTokens,
	}
	return nil
}

// Get returns a registered prompt. Version 0 = latest.
func (r *PromptRegistry) Get(name string, version int) (*Prompt, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	versions, ok := r.versions[name]
	if !ok {
		return nil, fmt.Errorf("prompt %q not registered", name)
	}
	if version > 0 {
		p, ok := versions[version]
		if !ok {
			return nil, fmt.Errorf("prompt %q v%d not found", name, version)
		}
		return p, nil
	}
	// latest
	maxV := 0
	for v := range versions {
		if v > maxV {
			maxV = v
		}
	}
	return versions[maxV], nil
}

// List returns the registered (name, latest-version) pairs. Used by the
// /ai/status endpoint and the MCP ai_runtime_status tool.
func (r *PromptRegistry) List() []PromptEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]PromptEntry, 0, len(r.versions))
	for name, versions := range r.versions {
		maxV := 0
		for v := range versions {
			if v > maxV {
				maxV = v
			}
		}
		out = append(out, PromptEntry{Name: name, LatestVersion: maxV, Description: versions[maxV].Description})
	}
	return out
}

// PromptEntry is the public-listing shape.
type PromptEntry struct {
	Name          string `json:"name"`
	LatestVersion int    `json:"latest_version"`
	Description   string `json:"description"`
}

// Count returns the number of distinct prompt names.
func (r *PromptRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.versions)
}

// Render fills the prompt templates with input. The returned Request
// is ready to hand to Runtime.Complete; the caller only needs to set
// MaxTokens (Render copies the prompt's default), Temperature, and the
// CompleteOptions.
func (p *Prompt) Render(input any) (Request, error) {
	var sys, usr strings.Builder
	if err := p.SystemTpl.Execute(&sys, input); err != nil {
		return Request{}, fmt.Errorf("system render: %w", err)
	}
	if err := p.UserTpl.Execute(&usr, input); err != nil {
		return Request{}, fmt.Errorf("user render: %w", err)
	}
	return Request{
		System:        sys.String(),
		User:          usr.String(),
		MaxTokens:     p.MaxTokens,
		PromptName:    p.Name,
		PromptVersion: p.Version,
	}, nil
}

// registerBuiltinPrompts seeds the registry with prompts that future
// phases will call into. Adding them now means the runtime ships with a
// usable prompt surface from day one; Phase 11.1 (clarifier) will edit
// `signer_clarifier` rather than introducing it from scratch.
func registerBuiltinPrompts(r *PromptRegistry) {
	// Signer clarifier (Phase 11.1). Highlight a clause, get a plain-
	// language explanation grounded in the clause + relevant Swedish/EU
	// legal references. The clarifier-grounding documents (EDPB Q&As,
	// Avtalslagen excerpts) are passed via Input.LegalContext.
	_ = r.Register("signer_clarifier", 1,
		"Plain-language explanation of a contract clause for the signer, grounded in Swedish/EU legal context.",
		`You are a plain-language legal explainer for a signer reading a contract.
Stay short (3-5 sentences). Translate jargon into everyday Swedish or English to match the signer's locale.
Never invent legal rights that aren't supported by the supplied legal context. If unsure, say so plainly.`,
		`Locale: {{.Locale}}
Clause text:
{{.ClauseText}}

Document context (surrounding clauses):
{{.SurroundingContext}}

Relevant legal context (Avtalslagen / EDPB / etc):
{{.LegalContext}}

Signer question (may be empty for "explain this"):
{{.Question}}`,
		512,
	)

	// Negotiation counter-clause suggestion (Phase 11.2). Draft an
	// alternative for a flagged clause based on patterns that closed in
	// similar past deals.
	_ = r.Register("negotiation_counter", 1,
		"Draft a counter-clause alternative when a recipient flags an existing clause.",
		`You are drafting a counter-proposal for a contract clause. Produce two outputs:
1. A revised clause body that addresses the recipient's concern while preserving the sender's intent.
2. A one-line rationale explaining the change.
Stay precise. Never weaken indemnity, IP, or liability caps without flagging the change explicitly.`,
		`Original clause:
{{.OriginalClause}}

Recipient concern / context:
{{.Concern}}

Sender's red lines (do NOT cross):
{{.RedLines}}`,
		768,
	)

	// Bilingual semantic-equivalence check (Phase 11.3).
	_ = r.Register("bilingual_equivalence", 1,
		"Verify two clauses in different languages say the same thing legally.",
		`You compare two clauses in different languages and report whether they say the same thing legally.
Output a JSON object: {"equivalent": bool, "drift": "<one-sentence summary or empty>", "confidence": float in 0..1}.
Only valid JSON. No prose.`,
		`Language A ({{.LangA}}):
{{.ClauseA}}

Language B ({{.LangB}}):
{{.ClauseB}}`,
		256,
	)

	// Risk analyser (v1.2 feature). Reads a draft document block-by-block
	// and flags clauses that contain elevated risk: liability caps too low
	// or absent, IP assignment that's broader than necessary, auto-renewal
	// without notice carve-outs, governing law / jurisdiction mismatches,
	// payment terms (NET-90+ is a flag), termination without cure period,
	// indemnification scope, etc. Strict JSON output so the caller can
	// render findings deterministically.
	_ = r.Register("risk_analyzer", 1,
		"Flag elevated-risk clauses in a contract draft with severity, category, and rewrite hints.",
		`You are a contract-risk reviewer for a Swedish business. Read the document blocks and identify clauses that contain elevated risk to the sender.
Categories: liability, ip, auto_renewal, jurisdiction, payment_terms, termination, indemnification, confidentiality, data_protection, warranty, other.
Severity scale: low (worth a heads-up), medium (recommend revision before signing), high (do not sign without revision).
Only flag clauses that are actually risky for the SENDER. Do not flag clauses that are merely uncommon or unusual.
Output STRICT JSON with shape {"findings": [{"block_id": "<id or empty>", "category": "<one of above>", "severity": "low|medium|high", "summary": "<short>", "suggestion": "<short>"}]}. No prose, no markdown.`,
		`Locale: {{.Locale}}

Document blocks (one per line, JSON-encoded):
{{.BlocksJSON}}

Sender context (their role, industry, redlines):
{{.SenderContext}}`,
		1536,
	)
}
