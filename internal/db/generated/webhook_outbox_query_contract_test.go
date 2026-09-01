// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package generated

import (
	"strings"
	"testing"
)

func TestWebhookOutboxQueriesAreDurableAndConcurrencySafe(t *testing.T) {
	for _, fragment := range []string{
		"JOIN webhook_endpoints",
		"ep.created_at <= ev.created_at",
		"NOT EXISTS",
		"ON CONFLICT (endpoint_id, event_id) DO NOTHING",
	} {
		if !strings.Contains(reconcileMissingWebhookDeliveries, fragment) {
			t.Errorf("reconciliation query missing safety clause %q\n%s", fragment, reconcileMissingWebhookDeliveries)
		}
	}

	for _, fragment := range []string{
		"FOR UPDATE SKIP LOCKED",
		"UPDATE webhook_deliveries",
		"interval '5 minutes'",
		"RETURNING",
	} {
		if !strings.Contains(claimDueWebhookDeliveries, fragment) {
			t.Errorf("claim query missing safety clause %q\n%s", fragment, claimDueWebhookDeliveries)
		}
	}
}
