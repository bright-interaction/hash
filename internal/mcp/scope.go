// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
)

const (
	mcpScopeRead           = "read"
	mcpScopeWriteAuthoring = "write:authoring"
	mcpScopeWriteWorkflow  = "write:workflow"
)

// mcpToolRequiredScopes is the single authorization contract for the complete
// MCP tool catalogue. Keeping the classification centralized makes scope drift
// reviewable and lets dispatch fail closed when a newly registered tool has not
// yet been classified.
//
// Authoring covers document/content and configuration changes. Workflow is
// deliberately narrower: actions that advance or terminate a ceremony, send
// communications, rotate signer links, or configure its automatic expiry.
var mcpToolRequiredScopes = map[string]string{
	// Read-only tools.
	"ai_list_prompts":               mcpScopeRead,
	"ai_runtime_status":             mcpScopeRead,
	"diff_document_versions":        mcpScopeRead,
	"download_audit_cert":           mcpScopeRead,
	"download_final_pdf":            mcpScopeRead,
	"export_evidence_package":       mcpScopeRead,
	"get_compliance_baseline":       mcpScopeRead,
	"get_document":                  mcpScopeRead,
	"get_document_engagement":       mcpScopeRead,
	"get_document_events":           mcpScopeRead,
	"get_document_telemetry_stream": mcpScopeRead,
	"get_document_timeline":         mcpScopeRead,
	"get_envelope_manifest":         mcpScopeRead,
	"get_evidence_manifest":         mcpScopeRead,
	"get_org_activity":              mcpScopeRead,
	"get_org_activity_leaderboard":  mcpScopeRead,
	"get_org_branding":              mcpScopeRead,
	"get_org_metrics":               mcpScopeRead,
	"get_org_subscription":          mcpScopeRead,
	"get_qes_session":               mcpScopeRead,
	"get_template":                  mcpScopeRead,
	"list_billing_invoices":         mcpScopeRead,
	"list_billing_plans":            mcpScopeRead,
	"list_compliance_flags":         mcpScopeRead,
	"list_document_fields":          mcpScopeRead,
	"list_document_versions":        mcpScopeRead,
	"list_documents":                mcpScopeRead,
	"list_eidas_rules":              mcpScopeRead,
	"list_envelope_children":        mcpScopeRead,
	"list_proposals":                mcpScopeRead,
	"list_recipients":               mcpScopeRead,
	"list_templates":                mcpScopeRead,
	"list_variable_bindings":        mcpScopeRead,
	"list_webhook_deliveries":       mcpScopeRead,
	"list_webhooks":                 mcpScopeRead,
	"preview_eidas_rules":           mcpScopeRead,
	"preview_resolved_variables":    mcpScopeRead,
	"resolve_document_branding":     mcpScopeRead,
	"search_documents":              mcpScopeRead,

	// Document/content and configuration authoring.
	"add_document_field":               mcpScopeWriteAuthoring,
	"add_recipient":                    mcpScopeWriteAuthoring,
	"add_signature_field":              mcpScopeWriteAuthoring,
	"append_block":                     mcpScopeWriteAuthoring,
	"attach_metadata":                  mcpScopeWriteAuthoring,
	"attach_to_envelope":               mcpScopeWriteAuthoring,
	"bind_variable_to_crm_contact":     mcpScopeWriteAuthoring,
	"bind_variable_to_crm_deal":        mcpScopeWriteAuthoring,
	"bind_variable_to_org_setting":     mcpScopeWriteAuthoring,
	"bind_variable_to_scanner_finding": mcpScopeWriteAuthoring,
	"check_bilingual_equivalence":      mcpScopeWriteAuthoring,
	"clarify_clause":                   mcpScopeWriteAuthoring,
	"create_document":                  mcpScopeWriteAuthoring,
	"create_eidas_rule":                mcpScopeWriteAuthoring,
	"create_envelope":                  mcpScopeWriteAuthoring,
	"create_pdf_document":              mcpScopeWriteAuthoring,
	"create_webhook":                   mcpScopeWriteAuthoring,
	"delete_block":                     mcpScopeWriteAuthoring,
	"delete_document_field":            mcpScopeWriteAuthoring,
	"delete_eidas_rule":                mcpScopeWriteAuthoring,
	"delete_recipient":                 mcpScopeWriteAuthoring,
	"delete_webhook":                   mcpScopeWriteAuthoring,
	"detach_from_envelope":             mcpScopeWriteAuthoring,
	"import_html":                      mcpScopeWriteAuthoring,
	"import_markdown":                  mcpScopeWriteAuthoring,
	"promote_to_envelope":              mcpScopeWriteAuthoring,
	"propose_counter_clause":           mcpScopeWriteAuthoring,
	"reorder_blocks":                   mcpScopeWriteAuthoring,
	"reorder_envelope_children":        mcpScopeWriteAuthoring,
	"restore_document_version":         mcpScopeWriteAuthoring,
	"run_risk_analysis":                mcpScopeWriteAuthoring,
	"seed_compliance_baseline":         mcpScopeWriteAuthoring,
	"seed_swedish_eidas_defaults":      mcpScopeWriteAuthoring,
	"set_compliance_flag_status":       mcpScopeWriteAuthoring,
	"set_document_blocks":              mcpScopeWriteAuthoring,
	"set_document_routing_tier":        mcpScopeWriteAuthoring,
	"set_org_branding":                 mcpScopeWriteAuthoring,
	"set_proposal_status":              mcpScopeWriteAuthoring,
	"set_variables":                    mcpScopeWriteAuthoring,
	"suggest_counter_clause":           mcpScopeWriteAuthoring,
	"unbind_variable":                  mcpScopeWriteAuthoring,
	"update_block":                     mcpScopeWriteAuthoring,
	"update_recipient":                 mcpScopeWriteAuthoring,

	// Outward ceremony and lifecycle actions.
	"remind_recipient": mcpScopeWriteWorkflow,
	"send_document":    mcpScopeWriteWorkflow,
	"set_expiry":       mcpScopeWriteWorkflow,
	"void_document":    mcpScopeWriteWorkflow,
}

var mcpResourceRequiredScopes = map[string]string{
	"hash://meta/capabilities": mcpScopeRead,
	"hash://schema/blocks":     mcpScopeRead,
	"hash://users/me":          mcpScopeRead,
	"hash://documents/recent":  mcpScopeRead,
	"hash://events/recent":     mcpScopeRead,
}

func validMCPRequiredScope(scope string) bool {
	switch scope {
	case mcpScopeRead, mcpScopeWriteAuthoring, mcpScopeWriteWorkflow:
		return true
	default:
		return false
	}
}

// hasMCPRequiredScope enforces exact granular scopes for org API keys. Existing
// document-agent-token rows may predate the granular vocabulary and carry bare
// "write" or "sign" capabilities, so those aliases are honored only when the
// request also carries a document boundary. Human/internal callers without a
// token-scope marker retain full access, while RequireAPIKey always attaches the
// marker in production.
func hasMCPRequiredScope(ctx context.Context, required string) bool {
	if !validMCPRequiredScope(required) {
		return false
	}
	if _, tokenAuth := auth.TokenScopesFromContext(ctx); !tokenAuth {
		return true
	}
	if auth.HasScope(ctx, required) {
		return true
	}
	if !strings.HasPrefix(required, "write:") {
		return false
	}
	// Bare write/sign are legacy document-token capabilities. They must never
	// collapse the granular authoring/workflow boundary for an org API key.
	if _, documentToken := auth.DocumentScopeFromContext(ctx); !documentToken {
		return false
	}
	if auth.HasScope(ctx, "write") {
		return true
	}
	return required == mcpScopeWriteWorkflow && auth.HasScope(ctx, "sign")
}

// scopedDocLookup is the single doc-fetch primitive MCP tools should
// call. It enforces:
//
//  1. the v1.1 per-document agent-token scope (auth.EnforceDocScope),
//     so a scoped token cannot read documents other than its bound one;
//  2. the standard org-membership check via the existing
//     Queries.GetDocument OrgID parameter.
//
// Returns the document on success, a "document not found" error on
// pgx.ErrNoRows or scope mismatch, and the raw error for anything else.
//
// Tools that previously called d.Queries.GetDocument directly should
// migrate to this helper so the scope check lands once + everywhere.
func scopedDocLookup(ctx context.Context, q *generated.Queries, docID, orgID uuid.UUID) (*generated.Document, error) {
	if err := auth.EnforceDocScope(ctx, docID); err != nil {
		return nil, err
	}
	doc, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: docID, OrgID: orgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("document not found")
		}
		return nil, err
	}
	return doc, nil
}

// docScopeSafeTools is the fail-closed allow-list of MCP tools a per-document
// agent token (v1.1) may invoke. A tool belongs here iff it operates on a
// single document bound by the token: every entry either calls
// auth.EnforceDocScope (which rejects a target other than the token's document)
// or self-confines to the scoped document (list_documents / search_documents).
//
// Any tool NOT listed - every org-level tool (branding, eidas rules, webhooks,
// compliance, billing, org metrics, create_document / create_pdf_document /
// create_envelope, ...) - is refused for a doc-scoped token centrally in
// handleToolsCall. That makes confinement fail closed: the per-handler
// EnforceDocScope pattern silently leaks whenever a new org-level tool forgets
// the guard (that is exactly how list_webhooks / set_org_branding /
// create_eidas_rule became reachable by a doc token), whereas an allow-list
// confines every current AND future org-level tool by default.
var docScopeSafeTools = map[string]bool{
	// read (get_document/list_recipients/get_document_events call EnforceDocScope;
	// list_documents + search_documents self-confine to the scoped doc)
	"get_document": true, "list_recipients": true, "get_document_events": true,
	"list_documents": true, "search_documents": true,
	// authoring (all EnforceDocScope on the target doc)
	"set_document_blocks": true, "import_html": true, "import_markdown": true,
	"append_block": true, "delete_block": true, "reorder_blocks": true,
	"add_signature_field": true, "set_variables": true, "add_recipient": true,
	"update_recipient": true, "delete_recipient": true,
	// workflow
	"send_document": true, "void_document": true, "remind_recipient": true,
	"set_expiry": true, "attach_metadata": true,
	// versions
	"list_document_versions": true, "diff_document_versions": true, "restore_document_version": true,
	// variable bindings (bind_variable_to_org_setting is org-level -> excluded)
	"list_variable_bindings": true, "unbind_variable": true, "preview_resolved_variables": true,
	// engagement
	"get_document_engagement": true, "get_document_telemetry_stream": true,
	// branding (org-level get/set_org_branding excluded)
	"resolve_document_branding": true,
	// envelopes (create_envelope is org-level -> excluded)
	"promote_to_envelope": true, "attach_to_envelope": true, "detach_from_envelope": true,
	"reorder_envelope_children": true, "list_envelope_children": true, "get_envelope_manifest": true,
	// eidas (org-level rule CRUD excluded; per-doc tier is safe)
	"set_document_routing_tier": true,
	// evidence
	"download_final_pdf": true, "download_audit_cert": true,
	"get_evidence_manifest": true, "export_evidence_package": true,
	// ai apps
	"clarify_clause": true, "suggest_counter_clause": true, "propose_counter_clause": true,
	"set_proposal_status": true, "list_proposals": true, "run_risk_analysis": true,
	"check_bilingual_equivalence": true,
	// historical QES archive (read-only; no lifecycle operations are exposed)
	"get_qes_session": true,
	// fields
	"add_document_field": true, "list_document_fields": true, "delete_document_field": true,
	// timeline (org-level get_org_activity* excluded)
	"get_document_timeline": true,
}

// docScopeSafeResources is the fail-closed allow-list of MCP resources a
// per-document token may read. Resources do not carry arguments, so an
// org-wide feed cannot be narrowed to the token's document at dispatch time.
// Keep only static product metadata/schema and the already-authenticated
// caller identity here; document and event feeds expose sibling records.
var docScopeSafeResources = map[string]bool{
	"hash://meta/capabilities": true,
	"hash://schema/blocks":     true,
	"hash://users/me":          true,
}

// docTokenAllows reports whether a request may call the named tool given its
// scope. Org-wide API keys and session callers (no DocumentScopeKey in context)
// are always allowed here; only per-document agent tokens are confined to
// docScopeSafeTools. Fail closed: an unknown/new tool is denied for a doc token.
//
// A name in docScopeSafeTools that is not currently registered (e.g. an optional
// engine like Versions is absent on an un-migrated stack, so its tools are not
// mounted) is harmless: an unregistered tool is rejected as "unknown tool"
// before this gate is reached. The allow-list may therefore be a superset of the
// live tool set. Drift the other way (a typo that over-restricts a real doc
// tool) is caught by TestDocScopeSafeToolsAreRegistered, not at boot, so a
// missing optional engine never blocks startup.
func docTokenAllows(ctx context.Context, tool string) bool {
	if _, scoped := auth.DocumentScopeFromContext(ctx); !scoped {
		return true
	}
	return docScopeSafeTools[tool]
}

// docTokenAllowsResource applies the same default-deny boundary to
// resources/read. Any new resource is unavailable to document tokens until it
// is explicitly reviewed and added to docScopeSafeResources.
func docTokenAllowsResource(ctx context.Context, uri string) bool {
	if _, scoped := auth.DocumentScopeFromContext(ctx); !scoped {
		return true
	}
	return docScopeSafeResources[uri]
}
