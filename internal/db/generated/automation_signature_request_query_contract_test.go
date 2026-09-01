// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package generated

import (
	"os"
	"strings"
	"testing"
)

func TestAutomationSignatureRequestMigrationPreservesReplayTombstones(t *testing.T) {
	raw, err := os.ReadFile("../migrations/00063_automation_signature_requests.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, required := range []string{
		"unique (org_id, idempotency_key_hash)",
		"octet_length(idempotency_key_hash) = 32",
		"octet_length(request_hash) = 32",
		"references documents(id) on delete set null",
		"cannot roll back migration 00063 after durable automation signature requests exist",
		"preserve replay protection",
		"'automation'",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("automation signature request migration is missing %q", required)
		}
	}
	if strings.Contains(sql, "idempotency_key text") || strings.Contains(sql, "payload json") || strings.Contains(sql, "payload jsonb") {
		t.Fatal("automation replay table stores a raw key or customer payload")
	}
}

func TestAutomationSignatureRequestQueriesUseAtomicClaimAndLockedReplay(t *testing.T) {
	raw, err := os.ReadFile("../queries/automation_signature_requests.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, required := range []string{
		"on conflict (org_id, idempotency_key_hash) do nothing",
		"for update",
		"state = 'claimed'",
		"document_id is null",
		"state in ('ready', 'sent')",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("automation signature request queries are missing %q", required)
		}
	}
}
