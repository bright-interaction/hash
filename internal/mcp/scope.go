package mcp

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/db/generated"
)

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
	// qes
	"start_qes_session": true, "get_qes_session": true,
	// fields
	"add_document_field": true, "list_document_fields": true, "delete_document_field": true,
	// timeline (org-level get_org_activity* excluded)
	"get_document_timeline": true,
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
