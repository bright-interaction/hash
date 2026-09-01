// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These files own mutations whose accountability record is part of the
// security or legal contract. A direct Logger.Log call necessarily runs in a
// separate transaction, so reintroducing one here would permit the mutation to
// commit when the audit append fails. Operational telemetry files are omitted
// deliberately and remain best-effort.
func TestHighRiskMutationCallsitesDoNotUseNonTransactionalAudit(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	files := []string{
		"cmd/worker/quota_warnings.go",
		"internal/handler/ai_provider.go",
		"internal/handler/billing.go",
		"internal/handler/blocks.go",
		"internal/handler/branding.go",
		"internal/handler/compliance.go",
		"internal/handler/documents.go",
		"internal/handler/documents_import.go",
		"internal/handler/eidas.go",
		"internal/handler/envelopes.go",
		"internal/handler/fields.go",
		"internal/handler/members.go",
		"internal/handler/recipients.go",
		"internal/handler/templates.go",
		"internal/handler/variable_bindings.go",
		"internal/handler/versions.go",
		"internal/mcp/tools_authoring.go",
		"internal/mcp/tools_branding.go",
		"internal/mcp/tools_compliance.go",
		"internal/mcp/tools_eidas.go",
		"internal/mcp/tools_envelopes.go",
		"internal/mcp/tools_fields.go",
		"internal/mcp/tools_variable_bindings.go",
		"internal/mcp/tools_versions.go",
		"internal/mcp/tools_workflow.go",
	}
	for _, rel := range files {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if strings.Contains(string(body), ".Audit.Log(") {
			t.Errorf("%s uses nontransactional Audit.Log in a high-risk mutation module; use CommitMutation or LogTx", rel)
		}
	}
}
