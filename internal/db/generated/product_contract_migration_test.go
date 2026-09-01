// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package generated

import (
	"os"
	"strings"
	"testing"
)

func TestContractVariableMigrationInventoriesAndConstrainsEveryPersistedCopy(t *testing.T) {
	raw, err := os.ReadFile("../migrations/00054_contract_variable_shape.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, table := range []string{"templates", "documents", "document_versions"} {
		if !strings.Contains(sql, "select 1 from "+table+" where not hash_contract_variables_valid") {
			t.Fatalf("migration does not inventory %s before cutover", table)
		}
		if !strings.Contains(sql, "alter table "+table) || !strings.Contains(sql, table+"_contract_variables_shape") {
			t.Fatalf("migration does not constrain %s after inventory", table)
		}
	}
	for _, required := range []string{
		"variables_json = '[]'::jsonb",
		"jsonb_typeof(candidate) <> 'object'",
		"jsonb_typeof(entry.value) <> 'string'",
		"entry.key !~ '^[a-za-z_][a-za-z0-9_.]*$'",
		"raise exception",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("contract-variable migration is missing %q", required)
		}
	}
}

func TestPlanClaimMigrationRemovesUnsupportedEnterpriseFlags(t *testing.T) {
	raw, err := os.ReadFile("../migrations/00055_plan_claim_accuracy.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	up, _, ok := strings.Cut(sql, "-- +goose down")
	if !ok {
		t.Fatal("plan-claim migration is missing down boundary")
	}
	for _, unsupported := range []string{"'white_label'", "'sso'"} {
		if !strings.Contains(up, "features_json - "+unsupported) && !strings.Contains(up, "- "+unsupported) {
			t.Fatalf("up migration does not remove unsupported feature %s", unsupported)
		}
	}
	if !strings.Contains(up, "description = 'unlimited usage for larger teams. branding, evidence bundles, and mcp.'") {
		t.Fatal("up migration does not replace the unsupported Enterprise description")
	}
	if strings.Contains(up, "description = 'unlimited usage + white-label and sso.'") {
		t.Fatal("up migration still uses the unsupported Enterprise description")
	}
}

func TestLegacyTelemetrySummariesHaveBoundedRetention(t *testing.T) {
	query, err := os.ReadFile("../queries/telemetry.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(string(query)), "delete from document_engagement_summary\nwhere last_event_at < $1") {
		t.Fatal("legacy signer-engagement aggregates do not share the raw-event retention edge")
	}
	migration, err := os.ReadFile("../migrations/00057_telemetry_summary_retention.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(migration))
	if !strings.Contains(sql, "on document_engagement_summary(last_event_at)") {
		t.Fatal("engagement-summary retention cleanup lacks a bounded timestamp index")
	}
	up, down, ok := strings.Cut(sql, "-- +goose down")
	if !ok {
		t.Fatal("telemetry-retention migration is missing down boundary")
	}
	if !strings.Contains(up, "drop table document_engagement_summary_h1_backup") {
		t.Fatal("legacy H1 analytics snapshot remains outside the 90-day purge path")
	}
	if strings.Contains(down, "create table document_engagement_summary_h1_backup") ||
		strings.Contains(down, "insert into document_engagement_summary_h1_backup") {
		t.Fatal("telemetry-retention rollback recreates the deleted personal-data snapshot")
	}
	if !strings.Contains(down, "restore the verified release backup instead") {
		t.Fatal("irreversible telemetry snapshot deletion lacks an explicit recovery path")
	}
}

func TestSESOnlyCutoverInventoriesAndConstrainsLegacyHigherTierState(t *testing.T) {
	raw, err := os.ReadFile("../migrations/00058_ses_only_cutover.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, required := range []string{
		"active and required_tier in ('aes', 'qes')",
		"routing_tier in ('aes', 'qes')",
		"status not in ('completed', 'declined', 'voided', 'expired')",
		"explicit owner deactivation",
		"explicit owner reset",
		"check (not active or required_tier = 'ses')",
		"documents_nonterminal_routing_tier_ses_only",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("SES-only cutover migration is missing %q", required)
		}
	}
}

func TestArticle13CeremonyEpochMigrationIsFailClosedAndOneWay(t *testing.T) {
	raw, err := os.ReadFile("../migrations/00061_article13_ceremony_epochs.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	up, down, ok := strings.Cut(sql, "-- +goose down")
	if !ok {
		t.Fatal("article 13 ceremony-epoch migration is missing down boundary")
	}

	for _, required := range []string{
		"status in ('sent', 'in_progress', 'changes_requested')",
		"article 13 epoch cutover requires every in-flight send sealing operation to be drained",
		"article 13 cutover requires every active sent/in_progress/changes_requested ceremony",
		"hash_article13_marker_is_valid",
		"hash_article13_marker_matches",
		"required_notice_schema",
		"required_notice_sent_at",
		"jsonb_typeof(payload -> 'required_notice_schema') is distinct from 'string'",
		"return coalesce(",
		"octet_length(marker.row_hash) is distinct from 32",
		"marker.document_id = d.id",
		"marker.org_id = d.org_id",
		"marker_sent_at::timestamptz desc",
		"add column article13_notice_epoch_at timestamptz not null",
		"retain_until = hash_evidence_retain_until(article13_notice_epoch_at, 7)",
		"documents_article13_active_ceremony_bound",
		"documents_article13_notice_epoch_immutable",
		"send_sealing_article13_epoch_immutable",
		"deferrable initially deferred",
		"active document lacks a valid article 13 marker for its authoritative ceremony epoch",
	} {
		if !strings.Contains(up, required) {
			t.Fatalf("article 13 ceremony-epoch migration is missing %q", required)
		}
	}

	if !strings.Contains(down, "cannot roll back article 13 ceremony epochs while an intent or post-cutover send commitment exists") {
		t.Fatal("article 13 ceremony-epoch rollback is not guarded after durable use")
	}
	for _, lock := range []string{
		"lock table documents in access exclusive mode",
		"lock table send_sealing_intents in access exclusive mode",
		"lock table events in access exclusive mode",
	} {
		if got := strings.Count(sql, lock); got != 2 {
			t.Fatalf("article 13 ceremony-epoch migration has %d occurrences of %q, want one in Up and one in Down", got, lock)
		}
	}
}
