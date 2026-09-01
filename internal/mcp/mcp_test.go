// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/compliance"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/versions"
)

// withSessionContext attaches a fake session user to the request, the way
// auth.RequireAPIKey would do in production. Tests skip the middleware so
// we can exercise the JSON-RPC server in isolation.
func withSessionContext(req *http.Request, orgID, userID uuid.UUID, role, email string) *http.Request {
	ctx := req.Context()
	ctx = context.WithValue(ctx, auth.UserIDKey, userID)
	ctx = context.WithValue(ctx, auth.OrgIDKey, orgID)
	ctx = context.WithValue(ctx, auth.RoleKey, role)
	ctx = context.WithValue(ctx, auth.EmailKey, email)
	return req.WithContext(ctx)
}

func withDocumentScope(req *http.Request, documentID uuid.UUID) *http.Request {
	ctx := context.WithValue(req.Context(), auth.DocumentScopeKey, documentID)
	return req.WithContext(ctx)
}

func withTokenScopes(req *http.Request, scopes ...string) *http.Request {
	ctx := context.WithValue(req.Context(), auth.TokenScopesKey, scopes)
	return req.WithContext(ctx)
}

func newTestServer() *Server {
	s := NewServer()
	s.RegisterTool(ToolDef{
		Name:        "get_document",
		Description: "echo args back",
		InputSchema: schemaObject(map[string]any{}, nil),
		Handler: func(_ *http.Request, args json.RawMessage) (any, error) {
			return map[string]any{"echo": string(args)}, nil
		},
	})
	s.RegisterResource(Resource{
		URI:         "hash://schema/blocks",
		Name:        "hello",
		Description: "static",
		MimeType:    "application/json",
		Loader:      func(_ *http.Request) (any, error) { return map[string]string{"x": "y"}, nil },
	})
	s.RegisterPrompt(Prompt{
		Name:        "greet",
		Description: "say hi",
		Renderer: func(_ map[string]string) ([]PromptMessage, error) {
			m := PromptMessage{Role: "user"}
			m.Content.Type = "text"
			m.Content.Text = "hi"
			return []PromptMessage{m}, nil
		},
	})
	return s
}

func rpc(t *testing.T, h http.Handler, method string, params any, withAuth bool) *response {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	if withAuth {
		req = withSessionContext(req, uuid.New(), uuid.New(), "owner", "test@example.com")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
	var resp response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rr.Body.String())
	}
	return &resp
}

func rpcToolWithScopes(t *testing.T, h http.Handler, name string, scopes []string, documentScoped bool) *response {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": name, "arguments": map[string]any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req = withSessionContext(req, uuid.New(), uuid.New(), "owner", "owner@example.test")
	req = withTokenScopes(req, scopes...)
	if documentScoped {
		req = withDocumentScope(req, uuid.New())
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var resp response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rr.Body.String())
	}
	return &resp
}

func decodedToolResult(t *testing.T, resp *response) ToolResult {
	t.Helper()
	raw, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatal(err)
	}
	var result ToolResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode tool result: %v (%s)", err, raw)
	}
	return result
}

func TestInitialize(t *testing.T) {
	s := newTestServer()
	resp := rpc(t, s.Handler(), "initialize", map[string]any{}, false)
	if resp.Error != nil {
		t.Fatalf("initialize errored: %+v", resp.Error)
	}
	resBytes, _ := json.Marshal(resp.Result)
	var r map[string]any
	_ = json.Unmarshal(resBytes, &r)
	si, ok := r["serverInfo"].(map[string]any)
	if !ok || si["name"] != "hash" {
		t.Errorf("missing or wrong serverInfo: %+v", r)
	}
}

func TestPing(t *testing.T) {
	resp := rpc(t, newTestServer().Handler(), "ping", map[string]any{}, false)
	if resp.Error != nil {
		t.Fatalf("ping errored: %+v", resp.Error)
	}
}

func TestToolsList(t *testing.T) {
	resp := rpc(t, newTestServer().Handler(), "tools/list", map[string]any{}, false)
	if resp.Error != nil {
		t.Fatalf("tools/list error: %+v", resp.Error)
	}
	resBytes, _ := json.Marshal(resp.Result)
	if !bytes.Contains(resBytes, []byte(`"name":"get_document"`)) {
		t.Errorf("missing get_document tool: %s", resBytes)
	}
}

func TestToolsCall_Unauthenticated(t *testing.T) {
	resp := rpc(t, newTestServer().Handler(), "tools/call",
		map[string]any{"name": "get_document", "arguments": map[string]any{"a": 1}}, false)
	if resp.Error == nil || resp.Error.Code != codeUnauthorized {
		t.Errorf("expected unauthorized, got %+v", resp)
	}
}

func TestToolsCall_Authenticated(t *testing.T) {
	resp := rpc(t, newTestServer().Handler(), "tools/call",
		map[string]any{"name": "get_document", "arguments": map[string]any{"hi": "there"}}, true)
	if resp.Error != nil {
		t.Fatalf("authed call errored: %+v", resp.Error)
	}
	// Tool result content[0].text is itself a JSON string, so look for the
	// escaped form `\"hi\":\"there\"` in the marshalled wire response.
	resBytes, _ := json.Marshal(resp.Result)
	if !bytes.Contains(resBytes, []byte(`hi`)) || !bytes.Contains(resBytes, []byte(`there`)) {
		t.Errorf("echo did not roundtrip args: %s", resBytes)
	}
}

func TestToolsCall_GranularScopesDoNotCrossAuthorizationClasses(t *testing.T) {
	called := map[string]int{}
	s := NewServer()
	for _, tool := range []ToolDef{
		{Name: "get_document", Handler: func(_ *http.Request, _ json.RawMessage) (any, error) {
			called["get_document"]++
			return map[string]any{"ok": true}, nil
		}},
		{Name: "set_document_blocks", Write: true, Handler: func(_ *http.Request, _ json.RawMessage) (any, error) {
			called["set_document_blocks"]++
			return map[string]any{"ok": true}, nil
		}},
		{Name: "send_document", Write: true, Handler: func(_ *http.Request, _ json.RawMessage) (any, error) {
			called["send_document"]++
			return map[string]any{"ok": true}, nil
		}},
	} {
		s.RegisterTool(tool)
	}

	tests := []struct {
		name      string
		tool      string
		scopes    []string
		wantError bool
	}{
		{"read permits read", "get_document", []string{"read"}, false},
		{"authoring without read cannot read", "get_document", []string{"write:authoring"}, true},
		{"workflow without read cannot read", "get_document", []string{"write:workflow"}, true},
		{"authoring permits authoring", "set_document_blocks", []string{"write:authoring"}, false},
		{"workflow cannot author", "set_document_blocks", []string{"write:workflow"}, true},
		{"read cannot author", "set_document_blocks", []string{"read"}, true},
		{"workflow permits send", "send_document", []string{"write:workflow"}, false},
		{"authoring cannot send", "send_document", []string{"write:authoring"}, true},
		{"read cannot send", "send_document", []string{"read"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := called[tc.tool]
			resp := rpcToolWithScopes(t, s.Handler(), tc.tool, tc.scopes, false)
			result := decodedToolResult(t, resp)
			if result.IsError != tc.wantError {
				t.Fatalf("isError = %v, want %v; result=%+v", result.IsError, tc.wantError, result)
			}
			wantCalls := before
			if !tc.wantError {
				wantCalls++
			}
			if called[tc.tool] != wantCalls {
				t.Fatalf("handler calls = %d, want %d", called[tc.tool], wantCalls)
			}
		})
	}
}

func TestToolsCall_BareWriteAliasIsDocumentTokenOnly(t *testing.T) {
	s := NewServer()
	s.RegisterTool(ToolDef{
		Name: "send_document", Write: true,
		Handler: func(_ *http.Request, _ json.RawMessage) (any, error) { return map[string]any{"ok": true}, nil },
	})
	orgResult := decodedToolResult(t, rpcToolWithScopes(t, s.Handler(), "send_document", []string{"write"}, false))
	if !orgResult.IsError {
		t.Fatal("org API key with bare write bypassed granular workflow scope")
	}
	docResult := decodedToolResult(t, rpcToolWithScopes(t, s.Handler(), "send_document", []string{"write"}, true))
	if docResult.IsError {
		t.Fatalf("legacy document token bare write was not preserved: %+v", docResult)
	}
}

func TestToolsCall_UnclassifiedToolFailsClosed(t *testing.T) {
	called := false
	s := NewServer()
	s.RegisterTool(ToolDef{
		Name: "future_tool",
		Handler: func(_ *http.Request, _ json.RawMessage) (any, error) {
			called = true
			return map[string]any{"ok": true}, nil
		},
	})
	result := decodedToolResult(t, rpcToolWithScopes(t, s.Handler(), "future_tool", []string{"admin"}, false))
	if !result.IsError || called {
		t.Fatalf("unclassified tool did not fail closed: result=%+v called=%v", result, called)
	}
}

func TestToolsCall_UnknownTool(t *testing.T) {
	resp := rpc(t, newTestServer().Handler(), "tools/call",
		map[string]any{"name": "nope"}, true)
	if resp.Error != nil {
		t.Fatalf("expected app-level error, got rpc error: %+v", resp.Error)
	}
	resBytes, _ := json.Marshal(resp.Result)
	if !bytes.Contains(resBytes, []byte(`"isError":true`)) {
		t.Errorf("expected isError=true: %s", resBytes)
	}
}

func TestResourcesList(t *testing.T) {
	resp := rpc(t, newTestServer().Handler(), "resources/list", map[string]any{}, false)
	resBytes, _ := json.Marshal(resp.Result)
	if !bytes.Contains(resBytes, []byte(`"uri":"hash://schema/blocks"`)) {
		t.Errorf("missing test resource: %s", resBytes)
	}
}

func TestResourcesList_DocumentTokenOnlyAdvertisesSafeResources(t *testing.T) {
	s := newTestServer()
	s.RegisterResource(Resource{URI: "hash://documents/recent", Name: "org documents"})
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "resources/list", "params": map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req = withSessionContext(req, uuid.New(), uuid.New(), "sender", "agent@example.test")
	req = withTokenScopes(req, "read")
	req = withDocumentScope(req, uuid.New())
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if bytes.Contains(rr.Body.Bytes(), []byte("hash://documents/recent")) {
		t.Fatalf("document token was advertised org-wide resource: %s", rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("hash://schema/blocks")) {
		t.Fatalf("document token was not advertised reviewed static resource: %s", rr.Body.String())
	}
}

func TestResourcesRead_Unauthenticated(t *testing.T) {
	resp := rpc(t, newTestServer().Handler(), "resources/read",
		map[string]any{"uri": "hash://schema/blocks"}, false)
	if resp.Error == nil || resp.Error.Code != codeUnauthorized {
		t.Errorf("expected unauthorized, got %+v", resp)
	}
}

func TestResourcesRead_Authenticated(t *testing.T) {
	resp := rpc(t, newTestServer().Handler(), "resources/read",
		map[string]any{"uri": "hash://schema/blocks"}, true)
	if resp.Error != nil {
		t.Fatalf("read failed: %+v", resp.Error)
	}
}

func TestResourcesRead_DocumentTokenDeniedByDefault(t *testing.T) {
	s := newTestServer()
	s.RegisterResource(Resource{
		URI: "hash://documents/recent", Name: "org documents", MimeType: "application/json",
		Loader: func(_ *http.Request) (any, error) { return map[string]any{"leak": true}, nil },
	})
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "resources/read",
		"params":  map[string]any{"uri": "hash://documents/recent"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req = withSessionContext(req, uuid.New(), uuid.New(), "sender", "agent@example.test")
	req = withTokenScopes(req, "read")
	req = withDocumentScope(req, uuid.New())
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	var resp response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != codeUnauthorized {
		t.Fatalf("document token read of unreviewed resource = %+v, want unauthorized", resp)
	}
}

func TestResourcesRead_DocumentTokenAllowsReviewedStaticResource(t *testing.T) {
	s := NewServer()
	s.RegisterResource(Resource{
		URI: "hash://schema/blocks", Name: "schema", MimeType: "application/json",
		Loader: func(_ *http.Request) (any, error) { return map[string]any{"safe": true}, nil },
	})
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "resources/read",
		"params":  map[string]any{"uri": "hash://schema/blocks"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req = withSessionContext(req, uuid.New(), uuid.New(), "sender", "agent@example.test")
	req = withTokenScopes(req, "read")
	req = withDocumentScope(req, uuid.New())
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	var resp response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("document token static resource read failed: %+v", resp.Error)
	}
}

func TestResourcesRead_OrgTokenPreservesReviewedResourceAccess(t *testing.T) {
	resp := rpc(t, newTestServer().Handler(), "resources/read",
		map[string]any{"uri": "hash://schema/blocks"}, true)
	if resp.Error != nil {
		t.Fatalf("org token resource read failed: %+v", resp.Error)
	}
}

func TestResourcesRead_RequiresReadScope(t *testing.T) {
	call := func(scopes ...string) *response {
		body, err := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": "resources/read",
			"params": map[string]any{"uri": "hash://schema/blocks"},
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		req = withSessionContext(req, uuid.New(), uuid.New(), "owner", "owner@example.test")
		req = withTokenScopes(req, scopes...)
		rr := httptest.NewRecorder()
		newTestServer().Handler().ServeHTTP(rr, req)
		var resp response
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return &resp
	}
	if resp := call("write:authoring"); resp.Error == nil || resp.Error.Code != codeUnauthorized {
		t.Fatalf("write-only token read resource response = %+v, want unauthorized", resp)
	}
	if resp := call("read"); resp.Error != nil {
		t.Fatalf("read-scoped token could not read resource: %+v", resp.Error)
	}
}

func TestResourcesRead_Unknown(t *testing.T) {
	resp := rpc(t, newTestServer().Handler(), "resources/read",
		map[string]any{"uri": "test://no-such"}, true)
	if resp.Error == nil || resp.Error.Code != codeNotFound {
		t.Errorf("expected not-found, got %+v", resp)
	}
}

func TestPromptsList(t *testing.T) {
	resp := rpc(t, newTestServer().Handler(), "prompts/list", map[string]any{}, false)
	resBytes, _ := json.Marshal(resp.Result)
	if !bytes.Contains(resBytes, []byte(`"name":"greet"`)) {
		t.Errorf("missing greet prompt: %s", resBytes)
	}
}

func TestUnknownMethod(t *testing.T) {
	resp := rpc(t, newTestServer().Handler(), "frobnicate", map[string]any{}, false)
	if resp.Error == nil || resp.Error.Code != codeMethodNotFound {
		t.Errorf("expected method-not-found, got %+v", resp)
	}
}

func TestNonPOSTRejected(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	newTestServer().Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code) // JSON-RPC keeps 200 even on error
	}
	var resp response
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Error == nil || resp.Error.Code != codeInvalidRequest {
		t.Errorf("expected invalid-request, got %+v", resp)
	}
}

func TestRealServer_AuthoringToolsRegistered(t *testing.T) {
	// Build the real server via New() to confirm authoring + read tools and
	// resources are all registered. Pass empty deps; we never call any tool.
	s := New(Deps{})
	requiredTools := []string{
		// Authoring (week 2)
		"create_document", "set_document_blocks", "import_html", "import_markdown",
		"append_block", "delete_block", "reorder_blocks",
		"add_signature_field", "add_recipient", "set_variables",
		// Read (week 2)
		"list_templates", "get_template", "list_documents", "get_document",
		"search_documents", "list_recipients", "get_document_events", "get_org_metrics",
		// Workflow (week 7)
		"send_document", "void_document", "remind_recipient", "set_expiry", "attach_metadata",
	}
	for _, name := range requiredTools {
		if _, ok := s.tools[name]; !ok {
			t.Errorf("required tool %q not registered", name)
		}
	}
	requiredResources := []string{
		"hash://meta/capabilities", "hash://schema/blocks",
		"hash://users/me", "hash://documents/recent", "hash://events/recent",
	}
	for _, uri := range requiredResources {
		if _, ok := s.resources[uri]; !ok {
			t.Errorf("required resource %q not registered", uri)
		}
	}
	requiredPrompts := []string{"draft_consulting_agreement", "extract_from_email", "document_brief"}
	for _, name := range requiredPrompts {
		if _, ok := s.prompts[name]; !ok {
			t.Errorf("required prompt %q not registered", name)
		}
	}
}

// TestWriteToolsRequireOwnerRoleParity guards against the MCP<->REST RBAC gap:
// several write MCP tools mutate org-wide state whose REST twins are owner-only,
// but an unset MinRole defaults a write tool to sender. A sender-tier API key
// must not reach these over MCP.
func TestMCPToolsRequireOwnerRoleParity(t *testing.T) {
	s := NewServer()
	// Non-nil engines so the gated eidas + compliance tools register; the tool
	// Handlers are never invoked here, so zero-value pointers are enough.
	d := Deps{EIDAS: &eidas.Engine{}, Compliance: &compliance.Seeder{}}
	registerWebhookTools(s, d)
	registerEIDASTools(s, d)
	registerComplianceTools(s, d)
	registerBrandingTools(s, d)

	ownerOnly := []string{
		"list_webhooks", "list_webhook_deliveries",
		"create_webhook", "delete_webhook",
		"list_eidas_rules", "preview_eidas_rules",
		"create_eidas_rule", "delete_eidas_rule", "seed_swedish_eidas_defaults",
		"get_compliance_baseline", "list_compliance_flags",
		"seed_compliance_baseline", "set_compliance_flag_status",
		"set_org_branding",
	}
	for _, name := range ownerOnly {
		tool, ok := s.tools[name]
		if !ok {
			t.Errorf("expected tool %q to be registered", name)
			continue
		}
		if tool.MinRole != auth.RoleOwner {
			t.Errorf("MCP tool %q must be MinRole=owner to match its owner-only REST twin, got %q", name, tool.MinRole)
		}
	}
}

// fullServer builds a server with every register func mounted. Non-nil
// zero-value deps satisfy the `if d.X == nil { return }` guards so the gated
// surfaces (bindings, evidence, downloads, AI apps, the historical QES reader,
// ...) actually register.
// Handlers are never invoked here, so the engines never need to be real.
func fullServer() *Server {
	return New(Deps{
		Queries:      &generated.Queries{},
		Storage:      &storage.Client{},
		Audit:        &audit.Logger{},
		Versions:     &versions.Engine{},
		Resolver:     &resolver.Resolver{},
		AIRuntime:    &ai.Runtime{},
		Envelopes:    &envelopes.Engine{},
		EIDAS:        &eidas.Engine{},
		Evidence:     &evidence.Builder{},
		Clarifier:    &aiapps.Clarifier{},
		Negotiator:   &aiapps.Negotiator{},
		Bilingual:    &aiapps.Bilingual{},
		RiskAnalyzer: &aiapps.RiskAnalyzer{},
		Compliance:   &compliance.Seeder{},
		Billing:      &billing.Engine{},
		Send:         &send.Engine{},
	})
}

// TestMutatingToolsAreWriteFlagged is the regression guard for the class of bug
// where a state-mutating tool forgets `Write: true`. The zero value bypasses BOTH
// the write-scope check AND the RoleSender-default gate in handleToolsCall, so a
// read-only API key could reach it. Any tool whose name starts with a mutation
// verb MUST carry Write:true. (bind_ was the original offender.)
func TestMutatingToolsAreWriteFlagged(t *testing.T) {
	s := fullServer()
	mutatingPrefixes := []string{
		"bind_", "unbind_", "create_", "add_", "update_", "delete_", "set_",
		"send_", "void_", "remind_", "attach_", "detach_", "reorder_", "import_",
		"append_", "seed_", "promote_", "revise_", "start_", "remove_", "sign_",
	}
	for name, tool := range s.tools {
		for _, pre := range mutatingPrefixes {
			if strings.HasPrefix(name, pre) && !tool.Write {
				t.Errorf("MCP tool %q looks mutating (prefix %q) but Write=false; it bypasses the write-scope + RoleSender gate in handleToolsCall", name, pre)
				break
			}
		}
	}
}

func TestMCPRequiredScopeCatalogCoversEveryRegistration(t *testing.T) {
	s := fullServer()
	for name, tool := range s.tools {
		required, ok := mcpToolRequiredScopes[name]
		if !ok {
			t.Errorf("registered tool %q has no required-scope classification", name)
			continue
		}
		if !validMCPRequiredScope(required) {
			t.Errorf("registered tool %q has invalid required scope %q", name, required)
		}
		if tool.Write != (required != mcpScopeRead) {
			t.Errorf("registered tool %q Write=%v conflicts with required scope %q", name, tool.Write, required)
		}
	}
	for name := range mcpToolRequiredScopes {
		if _, ok := s.tools[name]; !ok {
			t.Errorf("required-scope catalog names unregistered tool %q", name)
		}
	}
	for uri := range s.resources {
		if required, ok := mcpResourceRequiredScopes[uri]; !ok || required != mcpScopeRead {
			t.Errorf("registered resource %q lacks read-scope classification", uri)
		}
	}
	for uri := range mcpResourceRequiredScopes {
		if _, ok := s.resources[uri]; !ok {
			t.Errorf("required-scope catalog names unregistered resource %q", uri)
		}
	}
}
