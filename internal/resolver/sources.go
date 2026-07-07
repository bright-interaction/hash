package resolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/brightinteraction/hash/internal/db/generated"
)

// httpDoer is the small subset of http.Client we need. Lets tests inject a
// fake without bringing in a mocking framework.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPSource is the shared scaffolding for crm.deal, crm.contact, and
// scanner.finding. They all do the same thing: bearer-authed GET against a
// configured base URL, JSON response, JSONPath-style lookup of a field.
type HTTPSource struct {
	BaseURL string // e.g. "https://crm.example.com"
	Token   string // bearer token; empty means "not configured"
	Client  httpDoer
	kind    SourceKind
	pathFor func(ref Ref) string // builds the URL path for a given ref
}

func (h *HTTPSource) Kind() SourceKind { return h.kind }

func (h *HTTPSource) Fetch(ctx context.Context, ref Ref) (string, error) {
	if h.BaseURL == "" || h.Token == "" {
		return "", ErrNotConfigured
	}
	if ref.Source == "" {
		return "", errors.New("source_ref required")
	}
	if h.Client == nil {
		h.Client = &http.Client{Timeout: 10 * time.Second}
	}
	url := strings.TrimRight(h.BaseURL, "/") + h.pathFor(ref)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := h.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s fetch: %w", h.kind, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", ErrNotFound
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
		return "", fmt.Errorf("%s fetch: %d %s", h.kind, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return "", err
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("%s decode: %w", h.kind, err)
	}
	val, ok := jsonPathLookup(doc, ref.Path)
	if !ok {
		return "", fmt.Errorf("%s: path %q not found in response", h.kind, ref.Path)
	}
	s, ok := stringify(val)
	if !ok {
		return "", fmt.Errorf("%s: path %q resolved to nil", h.kind, ref.Path)
	}
	return s, nil
}

// NewCRMDealSource builds the BrightCRM deal-by-id resolver. base is
// typically "https://crm.example.com" and token a Hash-minted
// API key. With both empty, every Fetch returns ErrNotConfigured so the UI
// shows a clear "configure CRM integration" message instead of a 500.
func NewCRMDealSource(base, token string) *HTTPSource {
	return &HTTPSource{
		BaseURL: base,
		Token:   token,
		kind:    SourceCRMDeal,
		pathFor: func(ref Ref) string {
			return "/api/v1/deals/" + ref.Source
		},
	}
}

// NewCRMContactSource builds the BrightCRM contact-by-id resolver.
func NewCRMContactSource(base, token string) *HTTPSource {
	return &HTTPSource{
		BaseURL: base,
		Token:   token,
		kind:    SourceCRMContact,
		pathFor: func(ref Ref) string {
			return "/api/v1/contacts/" + ref.Source
		},
	}
}

// NewScannerFindingSource builds the SVAR scan-by-id resolver. Path lookups
// like "summary.critical_count" are how proposals can pull "you have 3
// critical findings" into a generated MSA.
func NewScannerFindingSource(base, token string) *HTTPSource {
	return &HTTPSource{
		BaseURL: base,
		Token:   token,
		kind:    SourceScannerFind,
		pathFor: func(ref Ref) string {
			return "/api/v1/scans/" + ref.Source
		},
	}
}

// OrgSettingSource reads from the local hash.orgs row plus (when 8.5
// branding lands) the org_branding row. source_ref is unused; source_path
// names the field, e.g. "org.name", "branding.primary_hex".
type OrgSettingSource struct {
	Q *generated.Queries
}

func (OrgSettingSource) Kind() SourceKind { return SourceOrgSetting }

func (s *OrgSettingSource) Fetch(ctx context.Context, ref Ref) (string, error) {
	if ref.OrgID == uuid.Nil {
		return "", errors.New("org.setting: missing org context")
	}
	if !strings.HasPrefix(ref.Path, "org.") && !strings.HasPrefix(ref.Path, "branding.") {
		return "", fmt.Errorf("org.setting: unknown path scope %q (expected org.* or branding.*)", ref.Path)
	}
	if strings.HasPrefix(ref.Path, "org.") {
		org, err := s.Q.GetOrg(ctx, ref.OrgID)
		if err != nil {
			return "", fmt.Errorf("org.setting: %w", err)
		}
		switch ref.Path {
		case "org.name":
			return org.Name, nil
		case "org.plan":
			return org.Plan, nil
		case "org.id":
			return org.ID.String(), nil
		default:
			return "", fmt.Errorf("org.setting: unknown org field %q", ref.Path)
		}
	}
	// branding.* lookups will be answered by the Phase 8.5 org_branding
	// row when it lands. Until then, return ErrNotConfigured so the UI
	// shows "configure brand theming" rather than a 500.
	return "", ErrNotConfigured
}

// AgentComputedSource is a stand-in: the agent.computed source kind has no
// real fetch path; its values arrive via ResolveOptions.AgentOverrides at
// render time. This plugin exists so the dispatch map covers the kind, and
// returns a friendly error if a binding row sneaks in that depends on it
// without an override.
type AgentComputedSource struct{}

func (AgentComputedSource) Kind() SourceKind { return SourceAgentComputed }

func (AgentComputedSource) Fetch(_ context.Context, _ Ref) (string, error) {
	return "", errors.New("agent.computed: no override supplied at render time")
}

// jsonPathLookup walks a dotted path through a JSON-decoded map. Supports
// nested objects ("deal.amount") and array indices ("findings.0.severity").
// Returns (value, true) on hit, (nil, false) on miss.
func jsonPathLookup(root any, path string) (any, bool) {
	if path == "" {
		return root, true
	}
	cur := root
	for _, seg := range strings.Split(path, ".") {
		switch v := cur.(type) {
		case map[string]any:
			next, ok := v[seg]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			// numeric segment for array index
			idx, err := parseArrayIndex(seg)
			if err != nil || idx < 0 || idx >= len(v) {
				return nil, false
			}
			cur = v[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

func parseArrayIndex(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, errors.New("empty index")
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, errors.New("non-numeric index")
		}
		n = n*10 + int(ch-'0')
	}
	return n, nil
}
