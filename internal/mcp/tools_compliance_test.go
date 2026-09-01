// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"testing"

	"github.com/bright-interaction/hash/internal/compliance"
)

func TestComplianceLegalDraftSeederIsAbsentInProductionMCP(t *testing.T) {
	production := New(Deps{Compliance: &compliance.Seeder{}, Environment: "production"})
	if _, ok := production.tools["seed_compliance_baseline"]; ok {
		t.Fatal("production MCP exposed the unapproved compliance legal-draft seeder")
	}

	development := New(Deps{Compliance: &compliance.Seeder{}, Environment: "development"})
	tool, ok := development.tools["seed_compliance_baseline"]
	if !ok {
		t.Fatal("development MCP unexpectedly omitted the compliance seeder")
	}
	properties, _ := tool.InputSchema["properties"].(map[string]any)
	jurisdiction, _ := properties["jurisdiction"].(map[string]any)
	values, _ := jurisdiction["enum"].([]string)
	if len(values) != 1 || values[0] != "SE" {
		t.Fatalf("jurisdiction schema = %#v, want SE-only", jurisdiction)
	}
}
