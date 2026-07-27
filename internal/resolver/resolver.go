// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package resolver implements Phase 8.2: pluggable variable resolution.
//
// The block tree references template variables as `{{name}}` placeholders.
// Phase 1 (week 2) resolved them from a static k/v stored in
// documents.variables_json. Phase 8.2 adds a binding layer: each variable
// can be bound to an external source (BrightCRM deal/contact, SVAR scanner
// finding, Hash org setting) or to an agent-supplied value resolved at
// render time.
//
// Resolver chain:
//
//  1. agent override          (caller-supplied at the top of every render)
//  2. document static value   (documents.variables_json, today's behaviour)
//  3. binding fetch           (live from the configured source)
//  4. binding fallback        (literal in the binding row)
//  5. unset                   (the {{var}} placeholder stays in the rendered
//     output, which the editor highlights)
//
// On send the snapshot pipeline calls FreezeForSend, which materializes the
// final resolved values into the document_versions row. From that moment on
// every render of the sent document uses the frozen values regardless of
// what happens to the live binding.
package resolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// SourceKind enumerates the binding source plugins.
type SourceKind string

const (
	SourceStatic        SourceKind = "static"
	SourceCRMDeal       SourceKind = "crm.deal"
	SourceCRMContact    SourceKind = "crm.contact"
	SourceScannerFind   SourceKind = "scanner.finding"
	SourceOrgSetting    SourceKind = "org.setting"
	SourceAgentComputed SourceKind = "agent.computed"
)

// Valid reports whether s is one of the registered source kinds.
func (s SourceKind) Valid() bool {
	switch s {
	case SourceStatic, SourceCRMDeal, SourceCRMContact, SourceScannerFind, SourceOrgSetting, SourceAgentComputed:
		return true
	}
	return false
}

// Source plugins answer "what is the current value at this binding?".
// Implementations should:
//   - Be safe to call from multiple goroutines.
//   - Honour ctx cancellation for HTTP calls.
//   - Return ErrNotConfigured (or wrap it) when the source plugin lacks the
//     necessary credentials, so the caller can show a clear UI nudge instead
//     of a generic error.
//
// Source plugins do NOT consult the binding's fallback or the document's
// static variables_json; that's the resolver chain's job.
type Source interface {
	Kind() SourceKind
	Fetch(ctx context.Context, ref Ref) (string, error)
}

// Ref carries the binding row's source_ref + source_path so source plugins
// can look up the right entity and pluck the right field.
type Ref struct {
	OrgID  uuid.UUID
	DocID  uuid.UUID
	Source string // source_ref column, e.g. "deal_4f2c9e8a"
	Path   string // source_path column, e.g. "amount"
}

// ErrNotConfigured signals that a source plugin is missing credentials. The
// resolver propagates this so callers (UI, MCP) can render a "configure
// integration" hint instead of a 500.
var ErrNotConfigured = errors.New("source plugin not configured")

// ErrNotFound signals the source row was queried successfully but the
// referenced entity doesn't exist. Falls through to the binding's fallback.
var ErrNotFound = errors.New("source entity not found")

// Resolver chains a static-document layer, a per-document binding layer, and
// an optional agent-override layer. It is the single entry point used by
// every render path (preview, signer view, final PDF) so resolution rules
// stay in one place.
type Resolver struct {
	Q       *generated.Queries
	Sources map[SourceKind]Source
	Cache   *cache
}

// New builds a Resolver with the given source plugins. A static source is
// always registered automatically, since static values are an artifact of
// the document row, not of an external system.
func New(q *generated.Queries, sources ...Source) *Resolver {
	m := map[SourceKind]Source{
		SourceStatic: &staticSource{},
	}
	for _, s := range sources {
		m[s.Kind()] = s
	}
	return &Resolver{
		Q:       q,
		Sources: m,
		Cache:   newCache(30 * time.Second),
	}
}

// ResolveOptions tunes a single Resolve call.
type ResolveOptions struct {
	// AgentOverrides win over every other layer. Used by MCP callers that
	// already know the value (e.g. a workflow tool computing a derived value
	// before re-rendering for preview).
	AgentOverrides map[string]string
	// FreezeMode disables live binding fetches and uses last_value from the
	// binding row instead. Used by the send-time freeze and by re-renders of
	// already-sent documents (which cannot pick up new live data).
	FreezeMode bool
}

// Resolve produces the final variable map for a document. The block tree's
// HTML renderer accepts a map[string]string; this is what we hand it.
//
// It always also returns a per-binding ResolveReport so the audit log + UI
// can show which sources answered and which fell through to fallbacks.
func (r *Resolver) Resolve(ctx context.Context, doc *generated.Document, opts ResolveOptions) (map[string]string, []ResolveReport, error) {
	if doc == nil {
		return nil, nil, errors.New("resolve: nil document")
	}
	out := map[string]string{}
	report := []ResolveReport{}

	// Layer 1: document static values (variables_json).
	if len(doc.VariablesJson) > 0 {
		var statics map[string]any
		if err := json.Unmarshal(doc.VariablesJson, &statics); err == nil {
			for k, v := range statics {
				if s, ok := stringify(v); ok {
					out[k] = s
				}
			}
		}
	}

	// Layer 2: bindings.
	bindings, err := r.Q.ListVariableBindings(ctx, doc.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve: list bindings: %w", err)
	}
	for _, b := range bindings {
		entry := ResolveReport{
			Variable:   b.VariableName,
			SourceKind: b.SourceKind,
			SourceRef:  b.SourceRef,
			SourcePath: b.SourcePath,
		}
		val, src := r.fetchOne(ctx, doc, b, opts)
		entry.ResolvedFrom = src
		if val != "" {
			out[b.VariableName] = val
			entry.Value = val
		} else if b.Fallback != "" {
			out[b.VariableName] = b.Fallback
			entry.Value = b.Fallback
			entry.ResolvedFrom = "fallback"
		}
		report = append(report, entry)
	}

	// Layer 3: agent overrides win.
	for k, v := range opts.AgentOverrides {
		out[k] = v
	}
	return out, report, nil
}

// FreezeForSend resolves every binding for a document and writes the result
// into the document's variables_json so the version snapshot captures it.
// After freeze, the document's bindings are kept (read-only) for audit
// transparency, but renders pull from the frozen variables_json.
//
// Callers (typically the send handler) should call FreezeForSend BEFORE
// transitioning the document status to 'sent' so the snapshot triggered by
// the state change captures the frozen values.
func (r *Resolver) FreezeForSend(ctx context.Context, doc *generated.Document) (json.RawMessage, []ResolveReport, error) {
	resolved, report, err := r.Resolve(ctx, doc, ResolveOptions{})
	if err != nil {
		return nil, nil, err
	}
	// Keep static values that weren't bound (they're already in variables_json
	// and resolved/report includes them). Just marshal the merged map.
	frozen, err := json.Marshal(resolved)
	if err != nil {
		return nil, nil, fmt.Errorf("freeze: marshal: %w", err)
	}
	return frozen, report, nil
}

// fetchOne runs the binding through the configured source, persists the
// result back to last_value/last_error, and returns the resolved string plus
// a label saying which layer answered ("source", "cached", "fallback", "").
func (r *Resolver) fetchOne(ctx context.Context, doc *generated.Document, b *generated.DocumentVariableBinding, opts ResolveOptions) (string, string) {
	if opts.FreezeMode {
		// Frozen renders read the last_value the resolver wrote at
		// freeze time; never touch external systems.
		return b.LastValue, "frozen"
	}
	if b.SourceKind == string(SourceStatic) {
		// 'static' bindings exist so the UI shows them as a row, but the
		// actual value comes from variables_json (already merged in Resolve
		// before fetchOne). Skip the source plugin.
		return "", ""
	}
	src, ok := r.Sources[SourceKind(b.SourceKind)]
	if !ok {
		_ = r.Q.UpdateVariableBindingError(ctx, generated.UpdateVariableBindingErrorParams{
			DocumentID:   b.DocumentID,
			VariableName: b.VariableName,
			LastError:    fmt.Sprintf("source kind %q not registered", b.SourceKind),
		})
		return "", ""
	}
	cacheKey := fmt.Sprintf("%s|%s|%s|%s",
		doc.OrgID.String(), b.SourceKind, b.SourceRef, b.SourcePath)
	if hit, ok := r.Cache.get(cacheKey); ok {
		return hit, "cached"
	}
	val, err := src.Fetch(ctx, Ref{
		OrgID:  doc.OrgID,
		DocID:  b.DocumentID,
		Source: b.SourceRef,
		Path:   b.SourcePath,
	})
	if err != nil {
		_ = r.Q.UpdateVariableBindingError(ctx, generated.UpdateVariableBindingErrorParams{
			DocumentID:   b.DocumentID,
			VariableName: b.VariableName,
			LastError:    err.Error(),
		})
		return "", ""
	}
	_ = r.Q.UpdateVariableBindingResolved(ctx, generated.UpdateVariableBindingResolvedParams{
		DocumentID:   b.DocumentID,
		VariableName: b.VariableName,
		LastValue:    val,
	})
	r.Cache.put(cacheKey, val)
	return val, "source"
}

// ResolveReport is one row in the per-document resolve audit. Returned to
// callers so the editor's debug panel + the audit log can show which path
// each variable took.
type ResolveReport struct {
	Variable     string `json:"variable"`
	SourceKind   string `json:"source_kind"`
	SourceRef    string `json:"source_ref,omitempty"`
	SourcePath   string `json:"source_path,omitempty"`
	Value        string `json:"value"`
	ResolvedFrom string `json:"resolved_from"` // "source" | "cached" | "fallback" | "frozen" | ""
}

// stringify coerces JSON-decoded values to strings for the variable map.
// Strings are returned verbatim; numbers and bools stringify reasonably;
// nested objects/arrays become their JSON representation.
func stringify(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case float64:
		// JSON numbers come out as float64. Avoid scientific notation for
		// reasonable amounts.
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t)), true
		}
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", t), "0"), "."), true
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	case nil:
		return "", false
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return "", false
		}
		return string(raw), true
	}
}

// cache is a thin per-process LRU keyed by source+ref+path. 30s TTL means
// the editor reload cycle reuses the same value but a freshly-saved BrightCRM
// edit propagates within half a minute.
type cache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]cacheEntry
}

type cacheEntry struct {
	value string
	at    time.Time
}

func newCache(ttl time.Duration) *cache {
	return &cache{ttl: ttl, m: map[string]cacheEntry{}}
}

func (c *cache) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return "", false
	}
	if time.Since(e.at) > c.ttl {
		delete(c.m, key)
		return "", false
	}
	return e.value, true
}

func (c *cache) put(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = cacheEntry{value: value, at: time.Now()}
}

// InvalidateForSource drops every cache entry whose key references the
// supplied (sourceKind, sourceRef) tuple, regardless of org or path.
// Used by the BrightCRM webhook receiver in Phase 9.1: when BrightCRM
// emits deal.updated for deal_4f2c9e8a, every cached resolution that
// referenced that deal becomes stale, so the next render re-fetches.
func (r *Resolver) InvalidateForSource(sourceKind, sourceRef string) int {
	if r == nil || r.Cache == nil {
		return 0
	}
	prefix := "|" + sourceKind + "|" + sourceRef + "|"
	r.Cache.mu.Lock()
	defer r.Cache.mu.Unlock()
	dropped := 0
	for k := range r.Cache.m {
		if strings.Contains(k, prefix) {
			delete(r.Cache.m, k)
			dropped++
		}
	}
	return dropped
}

// staticSource is registered automatically by New so the static SourceKind
// is always present in the dispatch map. Resolve handles the actual lookup
// from variables_json before fetchOne runs, so this Fetch is just a stub
// that returns no value (the caller falls through to the static layer).
type staticSource struct{}

func (staticSource) Kind() SourceKind                               { return SourceStatic }
func (staticSource) Fetch(_ context.Context, _ Ref) (string, error) { return "", nil }
