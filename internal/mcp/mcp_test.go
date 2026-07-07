package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/compliance"
	"github.com/brightinteraction/hash/internal/eidas"
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

func newTestServer() *Server {
	s := NewServer()
	s.RegisterTool(ToolDef{
		Name:        "echo",
		Description: "echo args back",
		InputSchema: schemaObject(map[string]any{}, nil),
		Handler: func(_ *http.Request, args json.RawMessage) (any, error) {
			return map[string]any{"echo": string(args)}, nil
		},
	})
	s.RegisterResource(Resource{
		URI:         "test://hello",
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
	if !bytes.Contains(resBytes, []byte(`"name":"echo"`)) {
		t.Errorf("missing echo tool: %s", resBytes)
	}
}

func TestToolsCall_Unauthenticated(t *testing.T) {
	resp := rpc(t, newTestServer().Handler(), "tools/call",
		map[string]any{"name": "echo", "arguments": map[string]any{"a": 1}}, false)
	if resp.Error == nil || resp.Error.Code != codeUnauthorized {
		t.Errorf("expected unauthorized, got %+v", resp)
	}
}

func TestToolsCall_Authenticated(t *testing.T) {
	resp := rpc(t, newTestServer().Handler(), "tools/call",
		map[string]any{"name": "echo", "arguments": map[string]any{"hi": "there"}}, true)
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
	if !bytes.Contains(resBytes, []byte(`"uri":"test://hello"`)) {
		t.Errorf("missing test resource: %s", resBytes)
	}
}

func TestResourcesRead_Unauthenticated(t *testing.T) {
	resp := rpc(t, newTestServer().Handler(), "resources/read",
		map[string]any{"uri": "test://hello"}, false)
	if resp.Error == nil || resp.Error.Code != codeUnauthorized {
		t.Errorf("expected unauthorized, got %+v", resp)
	}
}

func TestResourcesRead_Authenticated(t *testing.T) {
	resp := rpc(t, newTestServer().Handler(), "resources/read",
		map[string]any{"uri": "test://hello"}, true)
	if resp.Error != nil {
		t.Fatalf("read failed: %+v", resp.Error)
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
func TestWriteToolsRequireOwnerRoleParity(t *testing.T) {
	s := NewServer()
	// Non-nil engines so the gated eidas + compliance tools register; the tool
	// Handlers are never invoked here, so zero-value pointers are enough.
	d := Deps{EIDAS: &eidas.Engine{}, Compliance: &compliance.Seeder{}}
	registerWebhookTools(s, d)
	registerEIDASTools(s, d)
	registerComplianceTools(s, d)
	registerBrandingTools(s, d)

	ownerOnly := []string{
		"create_webhook", "delete_webhook",
		"create_eidas_rule", "delete_eidas_rule", "seed_swedish_eidas_defaults",
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
