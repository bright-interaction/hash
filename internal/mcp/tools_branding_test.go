// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSetOrgBrandingRejectsInvalidFontBeforeDatabaseReadOrMutation(t *testing.T) {
	t.Parallel()
	server := NewServer()
	registerBrandingTools(server, Deps{})
	tool := server.tools["set_org_branding"]

	for _, tc := range []struct {
		name string
		args string
	}{
		{name: "whitespace", args: `{"font_body":" \t\n "}`},
		{name: "CSS punctuation", args: `{"font_heading":"Inter;}*{display:none}"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tool.Handler(httptest.NewRequest("POST", "/mcp", nil), json.RawMessage(tc.args))
			if err == nil || !strings.Contains(err.Error(), "font_") {
				t.Fatalf("invalid font error = %v, want field-specific refusal", err)
			}
		})
	}
}
