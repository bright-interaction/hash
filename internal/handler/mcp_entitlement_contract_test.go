// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"os"
	"strings"
	"testing"
)

func TestMCPFeatureIsCheckedAtUseButDoesNotBlockStandaloneKeyIssuance(t *testing.T) {
	issuance, err := os.ReadFile("api_keys.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(issuance), `requireFeature(w, r, u.OrgID, "mcp")`) {
		t.Fatal("generic API-key issuance is coupled to the optional MCP entitlement")
	}

	routes, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(routes)
	for _, required := range []string{
		`r.Use(auth.RequireAPIKey(s.APIKeys))`,
		`requireFeature(w, req, u.OrgID, "mcp")`,
		`r.Mount("/", s.MCP.Handler())`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("MCP route is missing entitlement contract %q", required)
		}
	}
}
