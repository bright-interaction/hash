// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package mcp speaks the Model Context Protocol over Streamable HTTP.
// JSON-RPC 2.0 envelope, single endpoint at `/mcp`, behind API-key auth.
//
// Phase 1 (this file's debut) ships read tools plus authoring write tools.
// Workflow tools (send_document, void, remind) come in week 4 alongside
// the SMTP and reminder worker plumbing.
package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
)

// sanitizeToolError keeps a tool's operator-authored validation message
// (not-found / bad-uuid / permission / quota) but replaces a raw pgx/SQL or
// connection error with a generic string, logging the real one server-side.
// The REST surface enforces the same discipline (writeInternalError); without
// this an agent would see SQLSTATE + column/constraint names or "dial tcp
// host:port" internal hostnames in result.content on any DB fault.
func sanitizeToolError(err error) string {
	var pgErr *pgconn.PgError
	var connErr *pgconn.ConnectError
	msg := err.Error()
	if errors.As(err, &pgErr) || errors.As(err, &connErr) ||
		strings.Contains(msg, "dial tcp") || strings.Contains(msg, "SQLSTATE") ||
		strings.Contains(msg, "host=") || strings.Contains(msg, "connection refused") {
		slog.Error("mcp tool internal error", "err", err)
		return "internal error"
	}
	return msg
}

// Wire types. We keep envelopes flat, with `result` or `error` populated
// but never both. ID may be a string, number, or null per JSON-RPC 2.0.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// JSON-RPC 2.0 reserved error codes plus our app-level codes.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603

	// Application-level (range -32000..-32099 reserved for the server).
	codeUnauthorized = -32001
	codeNotFound     = -32004
)

// ToolResult is the MCP-spec'd "tools/call" response payload. Each entry is
// a content fragment; we use type=text + JSON body for everything in v1.
type ToolResult struct {
	Content []ToolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ToolDef declares a registered tool. inputSchema is exposed at tools/list
// so the host LLM can call us with structured args.
type ToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	// Write marks a tool that mutates state. A token without the "write" scope
	// is refused at dispatch, so a read-only API token can only call read tools.
	Write bool `json:"-"`
	// MinRole is the minimum RBAC role required to call this tool. Empty means: a
	// Write tool defaults to RoleSender (so a write tool author cannot forget the
	// role gate the REST surface enforces via RequireRoleForWrites); a read tool
	// defaults to no role floor. Set explicitly (e.g. RoleOwner) to raise it.
	MinRole auth.Role `json:"-"`
	// MinFeature, when set, names a billing features_json capability the org must
	// have (qes / branding / evidence_bundle / ...). Enforced fail-closed centrally
	// so a paid-feature MCP tool cannot bypass the gate the REST handler applies.
	MinFeature string      `json:"-"`
	Handler    ToolHandler `json:"-"`
}

// ToolHandler runs a tool against the authenticated context (org_id +
// user_id are already in ctx via the auth middleware). It returns the JSON
// payload to put into result.content[0].text, or an error.
type ToolHandler func(r *http.Request, args json.RawMessage) (any, error)

// Resource is an MCP-spec'd resource. URI scheme is `hash://`.
type Resource struct {
	URI         string         `json:"uri"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	MimeType    string         `json:"mimeType"`
	Loader      ResourceLoader `json:"-"`
}

type ResourceLoader func(r *http.Request) (any, error)

// Prompt is a starter frame the MCP host surfaces in its UI.
type Prompt struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Arguments   []PromptArg    `json:"arguments,omitempty"`
	Renderer    PromptRenderer `json:"-"`
}

type PromptArg struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

type PromptRenderer func(args map[string]string) ([]PromptMessage, error)

type PromptMessage struct {
	Role    string `json:"role"`
	Content struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

// Server is the MCP entry point. Build via NewServer + Register*; mount via
// Handler() onto chi behind RequireAPIKey middleware.
type Server struct {
	tools     map[string]ToolDef
	resources map[string]Resource
	prompts   map[string]Prompt
	billing   *billing.Engine // for central MinFeature enforcement; nil = billing off (dev/e2e)
}

func NewServer() *Server {
	return &Server{
		tools:     map[string]ToolDef{},
		resources: map[string]Resource{},
		prompts:   map[string]Prompt{},
	}
}

func (s *Server) RegisterTool(t ToolDef) {
	s.tools[t.Name] = t
}

func (s *Server) RegisterResource(r Resource) {
	s.resources[r.URI] = r
}

func (s *Server) RegisterPrompt(p Prompt) {
	s.prompts[p.Name] = p
}

// Handler returns the http.Handler for the /mcp endpoint.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serve)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRPCError(w, nil, codeInvalidRequest, "POST required", nil)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeRPCError(w, nil, codeParseError, "read body: "+err.Error(), nil)
		return
	}
	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPCError(w, nil, codeParseError, "decode envelope: "+err.Error(), nil)
		return
	}
	if req.JSONRPC != "2.0" {
		writeRPCError(w, req.ID, codeInvalidRequest, "jsonrpc must be 2.0", nil)
		return
	}

	switch req.Method {
	case "initialize":
		s.handleInitialize(w, req)
	case "ping":
		writeRPCResult(w, req.ID, map[string]any{})
	case "tools/list":
		s.handleToolsList(w, req)
	case "tools/call":
		s.handleToolsCall(w, r, req)
	case "resources/list":
		s.handleResourcesList(w, req)
	case "resources/read":
		s.handleResourcesRead(w, r, req)
	case "prompts/list":
		s.handlePromptsList(w, req)
	case "prompts/get":
		s.handlePromptsGet(w, req)
	default:
		writeRPCError(w, req.ID, codeMethodNotFound, "unknown method: "+req.Method, nil)
	}
}

func (s *Server) handleInitialize(w http.ResponseWriter, req request) {
	writeRPCResult(w, req.ID, map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities": map[string]any{
			"tools":     map[string]any{"listChanged": false},
			"resources": map[string]any{"listChanged": false},
			"prompts":   map[string]any{"listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    "hash",
			"version": "0.1.0",
		},
		"instructions": "Hash: agent-native document creation and e-signing. Use tools/list to see available authoring + read tools, resources/list for live state and the block schema, prompts/list for starter frames. The block tree schema is at hash://schema/blocks.",
	})
}

func (s *Server) handleToolsList(w http.ResponseWriter, req request) {
	out := make([]ToolDef, 0, len(s.tools))
	for _, t := range s.tools {
		out = append(out, t)
	}
	writeRPCResult(w, req.ID, map[string]any{"tools": out})
}

func (s *Server) handleToolsCall(w http.ResponseWriter, r *http.Request, req request) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		writeRPCError(w, req.ID, codeInvalidParams, "decode params: "+err.Error(), nil)
		return
	}
	tool, ok := s.tools[p.Name]
	if !ok {
		writeRPCResult(w, req.ID, ToolResult{
			Content: []ToolContent{{Type: "text", Text: "unknown tool: " + p.Name}},
			IsError: true,
		})
		return
	}
	u, ok := auth.FromContext(r.Context())
	if !ok {
		writeRPCError(w, req.ID, codeUnauthorized, "no session in context", nil)
		return
	}
	// Per-document agent tokens (v1.1) are confined to their bound document: they
	// may only call tools in docScopeSafeTools (the doc-addressed tools that
	// EnforceDocScope + the self-confining list/search). Every org-level tool is
	// refused here fail-closed, so a doc token handed to a counterparty cannot
	// rewrite org branding, downgrade the org eIDAS signature tier, register an
	// org webhook, or enumerate sibling documents. Org-wide keys + sessions are
	// unaffected (no DocumentScopeKey in context).
	if !docTokenAllows(r.Context(), p.Name) {
		writeRPCResult(w, req.ID, ToolResult{
			Content: []ToolContent{{Type: "text", Text: "this token is scoped to a single document and cannot call the org-level '" + p.Name + "' tool"}},
			IsError: true,
		})
		return
	}
	// Write tools require the "write" scope. A read-only API token (or a
	// scoped token without write) can call read tools but is refused here.
	if tool.Write && !auth.HasWriteScope(r.Context()) {
		writeRPCResult(w, req.ID, ToolResult{
			Content: []ToolContent{{Type: "text", Text: "this token is read-only; the '" + p.Name + "' tool requires a write scope"}},
			IsError: true,
		})
		return
	}
	// RBAC role gate (token scope and user role are independent axes). A write tool
	// defaults to RoleSender so it matches the REST RequireRoleForWrites gate even if
	// the registration forgot to set MinRole; this closes the demoted-viewer-with-
	// write-token bypass that let a viewer send/void/remind over MCP.
	minRole := tool.MinRole
	if minRole == "" && tool.Write {
		minRole = auth.RoleSender
	}
	if minRole != "" && !auth.RoleAtLeast(r.Context(), minRole) {
		writeRPCResult(w, req.ID, ToolResult{
			Content: []ToolContent{{Type: "text", Text: "insufficient role: '" + p.Name + "' requires at least " + string(minRole)}},
			IsError: true,
		})
		return
	}
	// Paid-feature gate, fail-closed, mirroring the REST requireFeature so a free-plan
	// org cannot reach a gated capability (qes / branding / evidence_bundle) via MCP.
	if tool.MinFeature != "" && s.billing != nil {
		entitled, ferr := s.billing.HasFeature(r.Context(), u.OrgID, tool.MinFeature)
		if ferr != nil || !entitled {
			msg := "your plan does not include the '" + tool.MinFeature + "' feature"
			if ferr != nil {
				msg = "entitlement check unavailable"
			}
			writeRPCResult(w, req.ID, ToolResult{
				Content: []ToolContent{{Type: "text", Text: msg}},
				IsError: true,
			})
			return
		}
	}
	result, err := tool.Handler(r, p.Arguments)
	if err != nil {
		writeRPCResult(w, req.ID, ToolResult{
			Content: []ToolContent{{Type: "text", Text: sanitizeToolError(err)}},
			IsError: true,
		})
		return
	}
	body, _ := json.Marshal(result)
	writeRPCResult(w, req.ID, ToolResult{
		Content: []ToolContent{{Type: "text", Text: string(body)}},
	})
}

func (s *Server) handleResourcesList(w http.ResponseWriter, req request) {
	out := make([]Resource, 0, len(s.resources))
	for _, r := range s.resources {
		out = append(out, r)
	}
	writeRPCResult(w, req.ID, map[string]any{"resources": out})
}

func (s *Server) handleResourcesRead(w http.ResponseWriter, r *http.Request, req request) {
	var p struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		writeRPCError(w, req.ID, codeInvalidParams, "decode params: "+err.Error(), nil)
		return
	}
	res, ok := s.resources[p.URI]
	if !ok {
		writeRPCError(w, req.ID, codeNotFound, "unknown resource: "+p.URI, nil)
		return
	}
	if _, ok := auth.FromContext(r.Context()); !ok {
		writeRPCError(w, req.ID, codeUnauthorized, "no session in context", nil)
		return
	}
	body, err := res.Loader(r)
	if err != nil {
		writeRPCError(w, req.ID, codeInternalError, err.Error(), nil)
		return
	}
	raw, _ := json.Marshal(body)
	writeRPCResult(w, req.ID, map[string]any{
		"contents": []map[string]any{{
			"uri":      p.URI,
			"mimeType": res.MimeType,
			"text":     string(raw),
		}},
	})
}

func (s *Server) handlePromptsList(w http.ResponseWriter, req request) {
	out := make([]Prompt, 0, len(s.prompts))
	for _, p := range s.prompts {
		out = append(out, p)
	}
	writeRPCResult(w, req.ID, map[string]any{"prompts": out})
}

func (s *Server) handlePromptsGet(w http.ResponseWriter, req request) {
	var p struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		writeRPCError(w, req.ID, codeInvalidParams, "decode params: "+err.Error(), nil)
		return
	}
	prompt, ok := s.prompts[p.Name]
	if !ok {
		writeRPCError(w, req.ID, codeNotFound, "unknown prompt: "+p.Name, nil)
		return
	}
	msgs, err := prompt.Renderer(p.Arguments)
	if err != nil {
		writeRPCError(w, req.ID, codeInternalError, err.Error(), nil)
		return
	}
	writeRPCResult(w, req.ID, map[string]any{
		"description": prompt.Description,
		"messages":    msgs,
	})
}

func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors are 200 with error body
	_ = json.NewEncoder(w).Encode(response{
		JSONRPC: "2.0",
		ID:      id,
		Error: &rpcError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	})
}

// MustParseArgs is a convenience for tool handlers that want strict-typed
// args. Returns a clean Go error so the server wraps it as ToolResult.
func MustParseArgs(raw json.RawMessage, into any) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return nil
}

// guard so the errors package import survives if we add typed-error helpers
// later without touching this file.
var _ = errors.New
