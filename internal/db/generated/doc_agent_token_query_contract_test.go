// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package generated

import (
	"os"
	"strings"
	"testing"
)

func TestDocumentAgentTokenClaimIsAtomicAndFailClosed(t *testing.T) {
	raw, err := os.ReadFile("../queries/doc_agent_tokens.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, required := range []string{
		"-- name: claimdocagenttokenuse :one",
		"set used_count   = used_count + 1",
		"revoked_at is null",
		"expires_at > now()",
		"max_uses = 0 or used_count < max_uses",
		"returning id",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("document token claim is missing %q", required)
		}
	}
}
