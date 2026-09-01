// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package generated

import (
	"strings"
	"testing"
)

func TestBrightCRMSourceLookupTargetsOnlyLiveDraftBindings(t *testing.T) {
	for _, required := range []string{
		"SELECT DISTINCT d.org_id",
		"JOIN documents AS d ON d.id = b.document_id",
		"b.source_kind = $1",
		"b.source_ref = $2",
		"d.status = 'draft'",
		"d.deleted_at IS NULL",
	} {
		if !strings.Contains(listOrgIDsForVariableSource, required) {
			t.Errorf("BrightCRM tenant lookup lacks %q", required)
		}
	}
}

func TestBrightCRMReceiptPreservesAuditedTenantSnapshot(t *testing.T) {
	for _, required := range []string{
		"delivery_correlation, payload_correlation, org_ids",
		"ON CONFLICT (delivery_correlation) DO NOTHING",
	} {
		if !strings.Contains(claimBrightCRMWebhookReceipt, required) {
			t.Errorf("BrightCRM receipt claim lacks %q", required)
		}
	}
	for _, required := range []string{
		"SELECT payload_correlation, org_ids",
		"WHERE delivery_correlation = $1",
	} {
		if !strings.Contains(getBrightCRMWebhookReceipt, required) {
			t.Errorf("BrightCRM receipt lookup lacks %q", required)
		}
	}
}

func TestBrightCRMReceiptPurgeIsBoundedAndContentionSafe(t *testing.T) {
	for _, required := range []string{
		"ORDER BY expires_at, delivery_correlation",
		"LIMIT 1000",
		"FOR UPDATE SKIP LOCKED",
	} {
		if !strings.Contains(purgeExpiredBrightCRMWebhookReceipts, required) {
			t.Errorf("BrightCRM receipt purge lacks %q", required)
		}
	}
}
