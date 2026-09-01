// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"strings"
	"testing"
)

func TestCreateWebhookDescriptionListsChangesRequested(t *testing.T) {
	t.Parallel()
	server := NewServer()
	registerWebhookTools(server, Deps{})
	tool, ok := server.tools["create_webhook"]
	if !ok {
		t.Fatal("create_webhook tool is not registered")
	}
	if !strings.Contains(tool.Description, "document.changes_requested") {
		t.Fatalf("create_webhook description omits public changes-requested event: %s", tool.Description)
	}
}
