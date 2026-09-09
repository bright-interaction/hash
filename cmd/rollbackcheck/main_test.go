// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRollbackResultJSONExposesEveryDurableBoundary(t *testing.T) {
	raw, err := json.Marshal(rollbackResult{
		Safe: false, Complete: true, SealingDocuments: 1, SendIntents: 2,
		FinalizingDocuments: 3, FinalizationIntents: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"safe":false`, `"complete":true`, `"sealing_documents":1`,
		`"send_sealing_intents":2`, `"finalizing_documents":3`,
		`"document_finalization_intents":4`,
	} {
		if !strings.Contains(string(raw), field) {
			t.Fatalf("rollback result %s is missing %s", raw, field)
		}
	}
}

func TestDatabaseIdentityModeExposesNoTargetOrCredentialMaterial(t *testing.T) {
	raw, err := json.Marshal(databaseIdentityResult{Safe: true, Complete: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"safe":true,"complete":true}` {
		t.Fatalf("database identity result = %s", raw)
	}
	for _, value := range []string{"", "0", "-1", "+1", "abc", strings.Repeat("1", 21)} {
		if validSystemIdentifier(value) {
			t.Errorf("invalid PostgreSQL system identifier %q accepted", value)
		}
	}
	for _, value := range []string{"1", "0123", "18446744073709551615"} {
		if !validSystemIdentifier(value) {
			t.Errorf("valid PostgreSQL system identifier %q rejected", value)
		}
	}
	for _, value := range []string{"", "0", "-1", "4294967296", "abc"} {
		if validDatabaseOID(value) {
			t.Errorf("invalid database OID %q accepted", value)
		}
	}
	for _, value := range []string{"1", "16384", "4294967295"} {
		if !validDatabaseOID(value) {
			t.Errorf("valid database OID %q rejected", value)
		}
	}
	for _, value := range []string{"", "Mithras", "9mithras", "bad-role", strings.Repeat("a", 64)} {
		if validDatabaseUsername(value) {
			t.Errorf("invalid database username %q accepted", value)
		}
	}
	for _, value := range []string{"mithras", "hash_app", "role9"} {
		if !validDatabaseUsername(value) {
			t.Errorf("valid database username %q rejected", value)
		}
	}
}

func TestDatabaseIdentityProofIsReadOnlyAndUsesPhysicalClusterIdentity(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "func verifyDatabaseIdentity")
	end := strings.Index(src[start:], "func validSystemIdentifier")
	if start < 0 || end < 0 {
		t.Fatal("database identity verifier is missing")
	}
	body := src[start : start+end]
	for _, required := range []string{
		"pgx.RepeatableRead", "pgx.ReadOnly", "current_database()", "session_user", "current_user",
		"pg_control_system()", "pg_database", "actualDatabaseOID == expectedDatabaseOID",
		"current_schema() = 'public'", "current_schemas(false) = ARRAY['public']::name[]",
		"NOT r.rolsuper", "NOT r.rolcreaterole", "NOT r.rolcreatedb", "NOT r.rolreplication", "NOT r.rolbypassrls",
		"leastPrivilegedDatabaseOwner",
	} {
		if !strings.Contains(body, required) {
			t.Errorf("database identity proof is missing %q", required)
		}
	}
	for _, forbidden := range []string{"INSERT ", "UPDATE ", "DELETE ", "TRUNCATE ", "HASH_DB_URL"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("database identity proof contains forbidden material %q", forbidden)
		}
	}
}

func TestDatabaseIdentityRejectsSchemaRoleAndDatabaseRecreationMismatch(t *testing.T) {
	args := []string{"hash", "mithras", "mithras", "7521111222233334444", "16384", "hash", "mithras", "7521111222233334444", "16384"}
	if !databaseIdentityMatches(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], true, true, true) {
		t.Fatal("exact database identity rejected")
	}
	for _, tc := range []struct {
		name                         string
		actualOID                    string
		canonicalSchema              bool
		canonicalSearchPath          bool
		leastPrivilegedDatabaseOwner bool
	}{
		{"drop-recreate-oid", "16385", true, true, true},
		{"current-schema", "16384", false, true, true},
		{"search-path", "16384", true, false, true},
		{"role-flags-or-owner", "16384", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if databaseIdentityMatches(args[0], args[1], args[2], args[3], tc.actualOID, args[5], args[6], args[7], args[8], tc.canonicalSchema, tc.canonicalSearchPath, tc.leastPrivilegedDatabaseOwner) {
				t.Fatal("database identity mismatch was accepted")
			}
		})
	}
}

func TestLawfulBasisCutoverResultExposesOnlyAggregateInventory(t *testing.T) {
	raw, err := json.Marshal(lawfulBasisCutoverResult{
		Safe: false, Complete: true, ActiveDocuments: 7, MissingMatchingConfirmations: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"safe":false`, `"complete":true`, `"active_documents":7`,
		`"missing_matching_confirmations":3`,
	} {
		if !strings.Contains(string(raw), field) {
			t.Fatalf("lawful-basis result %s is missing %s", raw, field)
		}
	}
}

func TestArticle13CutoverResultExposesOnlyAggregateInventory(t *testing.T) {
	raw, err := json.Marshal(article13CutoverResult{
		Safe: false, Complete: true, ActiveDocuments: 9, MissingMatchingMarkers: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"safe":false`, `"complete":true`, `"active_documents":9`,
		`"missing_matching_markers":2`,
	} {
		if !strings.Contains(string(raw), field) {
			t.Fatalf("Article 13 result %s is missing %s", raw, field)
		}
	}
}

func TestArticle13CutoverInventoryIsReadOnlyAndBindsEveryActiveDocument(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "func verifyArticle13CutoverBoundary")
	if start < 0 {
		t.Fatal("Article 13 cutover verifier is missing")
	}
	body := src[start:]
	for _, required := range []string{
		"pgx.RepeatableRead", "pgx.ReadOnly", "LEFT JOIN LATERAL",
		"d.article13_notice_epoch_at IS DISTINCT FROM d.sent_at",
		"hash_article13_marker_matches(", "marker.recipient_id IS NOT NULL",
		"octet_length(marker.row_hash) IS DISTINCT FROM 32",
		"d.status IN ('sent','in_progress','changes_requested')",
	} {
		if !strings.Contains(body, required) {
			t.Errorf("Article 13 inventory is missing %q", required)
		}
	}
	if strings.Contains(body, "d.parent_envelope_id IS NULL") {
		t.Fatal("Article 13 inventory skipped envelope child markers")
	}
	for _, forbidden := range []string{"INSERT ", "UPDATE ", "DELETE ", "TRUNCATE "} {
		if strings.Contains(body, forbidden) {
			t.Errorf("Article 13 inventory contains forbidden mutation %q", forbidden)
		}
	}
}

func TestLawfulBasisCutoverInventoryIsReadOnlyAndCoversEveryActiveState(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "func verifyLawfulBasisCutoverBoundary")
	if start < 0 {
		t.Fatal("lawful-basis cutover verifier is missing")
	}
	body := src[start:]
	for _, required := range []string{
		"pgx.RepeatableRead", "pgx.ReadOnly", "LEFT JOIN document_lawful_basis_confirmations",
		"c.org_id IS DISTINCT FROM d.org_id", "c.lawful_basis IS DISTINCT FROM d.lawful_basis",
		"d.parent_envelope_id IS NULL",
		"'sealing','sent','in_progress','finalizing','changes_requested'",
	} {
		if !strings.Contains(body, required) {
			t.Errorf("lawful-basis inventory is missing %q", required)
		}
	}
	for _, forbidden := range []string{"INSERT ", "UPDATE ", "DELETE ", "lawful_basis = 'contract'"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("lawful-basis inventory contains forbidden mutation/default marker %q", forbidden)
		}
	}
}

func TestLawfulBasisCutoverInventoryEvaluatesEnvelopeCeremonyRootsOnly(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "func verifyLawfulBasisCutoverBoundary")
	if start < 0 {
		t.Fatal("lawful-basis cutover verifier is missing")
	}
	body := src[start:]
	if !strings.Contains(body, "d.parent_envelope_id IS NULL") {
		t.Fatal("envelope child documents are counted as independent ceremonies; confirmation belongs to the root")
	}
}

func TestFirstInstallDatabaseProofRejectsAnyRecoveredHashSchema(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "func verifyFirstInstallDatabase")
	end := strings.Index(src[start:], "func verifyRollbackBoundary")
	if start < 0 || end < 0 {
		t.Fatal("first-install database verifier is missing or misplaced")
	}
	body := src[start : start+end]
	for _, required := range []string{
		"pgx.RepeatableRead", "pgx.ReadOnly", "pg_catalog.pg_class", "pg_catalog.pg_namespace",
		"n.nspname = 'public'", "c.relkind IN ('r', 'p')", "result.PublicApplicationTables == 0",
	} {
		if !strings.Contains(body, required) {
			t.Errorf("first-install proof is missing recovery-estate guard %q", required)
		}
	}
	if strings.Contains(body, "documents WHERE") {
		t.Fatal("first-install proof checks row emptiness instead of rejecting an existing/recovered schema")
	}
}

func TestFirstInstallSchemaProofBindsExactMigrationsAndEmptyEstate(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "func verifyFirstInstallSchema")
	end := strings.Index(src[start:], "func encodeResult")
	if start < 0 || end < 0 {
		t.Fatal("resumable first-install schema verifier is missing or misplaced")
	}
	body := src[start : start+end]
	for _, required := range []string{
		"hashdb.EmbeddedMigrationsIdentity()",
		"embeddedDigest != expectedDigest",
		"pgx.RepeatableRead", "pgx.ReadOnly",
		"DISTINCT ON (version_id)", "equalMigrationVersions(appliedVersions, embeddedVersions)",
		"c.relname NOT IN ('goose_db_version', 'billing_plans')",
		"pgx.Identifier{\"public\", tableName}.Sanitize()",
		"result.NonemptyBusinessTables++",
		"send_sealing_intents", "document_finalization_intents",
		"result.NonemptyBusinessTables == 0 && result.LifecycleIntents == 0",
	} {
		if !strings.Contains(body, required) {
			t.Errorf("post-migration first-install proof is missing %q", required)
		}
	}
	for _, forbidden := range []string{"INSERT ", "UPDATE ", "DELETE ", "TRUNCATE "} {
		if strings.Contains(body, forbidden) {
			t.Errorf("post-migration first-install proof contains forbidden mutation %q", forbidden)
		}
	}
}

func TestEqualMigrationVersionsRejectsMissingOrRolledBackState(t *testing.T) {
	want := []int64{1, 2, 4}
	for name, got := range map[string][]int64{
		"missing":    {1, 4},
		"unexpected": {1, 2, 3, 4},
		"reordered":  {1, 4, 2},
	} {
		if equalMigrationVersions(got, want) {
			t.Errorf("%s Goose state was accepted: %v", name, got)
		}
	}
	if !equalMigrationVersions([]int64{1, 2, 4}, want) {
		t.Fatal("exact Goose migration state was rejected")
	}
}

func TestFirstInstallCandidateCutoverRetryPreservesLegitimateRows(t *testing.T) {
	state := firstInstallSchemaResult{
		GooseStateExact:        true,
		StaticSeedExact:        true,
		NonemptyBusinessTables: 4,
		LifecycleIntents:       2,
	}
	if firstInstallSchemaSafe(state, true) {
		t.Fatal("pre-candidate schema phase accepted a nonempty business estate")
	}
	if !firstInstallSchemaSafe(state, false) {
		t.Fatal("durably authorized exact-candidate cutover could not resume after legitimate writes")
	}
	state.GooseStateExact = false
	if firstInstallSchemaSafe(state, false) {
		t.Fatal("candidate-cutover retry accepted a different Goose state")
	}
}
