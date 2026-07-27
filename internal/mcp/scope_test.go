// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/qes"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/versions"
)

// TestDocScopeSafeToolsMembership locks the allow-list: every doc-addressed tool
// stays reachable by a per-document token, and every org-level tool stays out
// (so a doc token cannot rewrite org branding, downgrade the org eIDAS tier,
// register an org webhook, enumerate the org, or mint new org documents).
func TestDocScopeSafeToolsMembership(t *testing.T) {
	mustAllow := []string{
		"get_document", "list_recipients", "get_document_events", "list_documents",
		"search_documents", "send_document", "void_document", "run_risk_analysis",
		"resolve_document_branding", "set_document_routing_tier",
		"list_envelope_children", "get_envelope_manifest", "download_final_pdf",
		"download_audit_cert", "start_qes_session", "add_document_field",
	}
	mustDeny := []string{
		"set_org_branding", "create_eidas_rule", "delete_eidas_rule",
		"seed_swedish_eidas_defaults", "create_webhook", "delete_webhook",
		"list_webhooks", "list_webhook_deliveries", "create_document",
		"create_pdf_document", "create_envelope", "seed_compliance_baseline",
		"set_compliance_flag_status", "get_org_metrics", "bind_variable_to_org_setting",
		"get_org_activity",
	}
	for _, n := range mustAllow {
		if !docScopeSafeTools[n] {
			t.Errorf("tool %q must be doc-scope-safe (a doc token needs it) but is not in the allow-list", n)
		}
	}
	for _, n := range mustDeny {
		if docScopeSafeTools[n] {
			t.Errorf("org-level tool %q must NOT be doc-scope-safe but is in the allow-list", n)
		}
	}
}

// TestDocTokenAllows checks the central gate: a doc-scoped context is confined
// to the allow-list; an org-wide / session context (no doc scope) is not.
func TestDocTokenAllows(t *testing.T) {
	docCtx := context.WithValue(context.Background(), auth.DocumentScopeKey, uuid.New())
	orgCtx := context.Background()

	if !docTokenAllows(docCtx, "get_document") {
		t.Error("doc token should be allowed to call get_document")
	}
	if docTokenAllows(docCtx, "set_org_branding") {
		t.Error("doc token must NOT be allowed to call the org-level set_org_branding")
	}
	if docTokenAllows(docCtx, "create_webhook") {
		t.Error("doc token must NOT be allowed to call the org-level create_webhook")
	}
	// A future/unknown tool fails closed for a doc token.
	if docTokenAllows(docCtx, "some_new_org_tool") {
		t.Error("doc token must fail closed on an unknown tool")
	}
	// Org-wide keys / sessions (no doc scope) are unaffected by the gate.
	if !docTokenAllows(orgCtx, "set_org_branding") {
		t.Error("an org-wide caller must still reach org-level tools")
	}
	if !docTokenAllows(orgCtx, "some_new_org_tool") {
		t.Error("an org-wide caller is not confined by the doc-scope allow-list")
	}
}

// TestDocScopeSafeToolsAreRegistered catches a typo/rename in the allow-list: a
// name that is not a real tool would silently over-restrict a doc token. The
// optional engines are set non-nil so their tool groups (versions, evidence,
// envelopes, ai apps, qes, eidas, variable bindings) all mount; registration
// only nil-checks the deps, so zero-value pointers are enough.
func TestDocScopeSafeToolsAreRegistered(t *testing.T) {
	s := New(Deps{
		Storage:      &storage.Client{},
		Evidence:     &evidence.Builder{},
		Versions:     &versions.Engine{},
		Envelopes:    &envelopes.Engine{},
		EIDAS:        &eidas.Engine{},
		QES:          &qes.Engine{},
		Resolver:     &resolver.Resolver{},
		Clarifier:    &aiapps.Clarifier{},
		Negotiator:   &aiapps.Negotiator{},
		Bilingual:    &aiapps.Bilingual{},
		RiskAnalyzer: &aiapps.RiskAnalyzer{},
	})
	for name := range docScopeSafeTools {
		if _, ok := s.tools[name]; !ok {
			t.Errorf("docScopeSafeTools names %q which is not a registered tool (typo/rename?)", name)
		}
	}
}
