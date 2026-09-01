// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package e2e

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	mdb "github.com/bright-interaction/hash/internal/db"
)

// A pre-control ceremony has no explicit controller instruction that Hash can
// safely invent. Migration 00052 must therefore be atomic and retryable: fail
// with the schema still at 51 while any ceremony is active, then succeed only
// after the operator has explicitly completed or terminated that inventory.
func TestLawfulBasisMigrationFailsClosedOnActivePrecontrolCeremony(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()

	migConn := stdlibConn(t, pool)
	defer migConn.Close()
	must(t, mdb.RunMigrationsUpTo(migConn, 51), "migrate scratch database to pre-control version 51")
	docID := seedDocument(t, ctx, pool, "lawful basis cutover")
	_, err := pool.Exec(ctx, `UPDATE documents SET status = 'sent' WHERE id = $1`, docID)
	must(t, err, "mark pre-control ceremony active")

	err = mdb.RunMigrationsUpTo(migConn, 52)
	if err == nil || !strings.Contains(err.Error(), "zero active pre-control ceremonies") {
		t.Fatalf("migration 00052 with an active ceremony = %v, want explicit inventory failure", err)
	}
	var applied int64
	must(t, pool.QueryRow(ctx, `SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&applied), "read failed migration version")
	if applied != 51 {
		t.Fatalf("failed migration advanced schema to %d, want 51", applied)
	}
	var confirmationTable pgtype.Text
	must(t, pool.QueryRow(ctx, `SELECT to_regclass('public.document_lawful_basis_confirmations')::text`).Scan(&confirmationTable), "inspect failed migration schema")
	if confirmationTable.Valid {
		t.Fatalf("failed migration left partial confirmation table %q", confirmationTable.String)
	}

	_, err = pool.Exec(ctx, `UPDATE documents SET status = 'completed' WHERE id = $1`, docID)
	must(t, err, "resolve pre-control ceremony inventory")
	must(t, mdb.RunMigrationsUpTo(migConn, 52), "retry lawful-basis migration after explicit remediation")
	must(t, pool.QueryRow(ctx, `SELECT to_regclass('public.document_lawful_basis_confirmations')::text`).Scan(&confirmationTable), "inspect successful migration schema")
	if !confirmationTable.Valid {
		t.Fatal("successful migration did not create the lawful-basis confirmation table")
	}
}

func TestSESOnlyMigrationRequiresExplicitLegacyStateRemediation(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	migConn := stdlibConn(t, pool)
	defer migConn.Close()
	must(t, mdb.RunMigrationsUpTo(migConn, 57), "migrate scratch database to pre-SES-cutover version 57")
	docID := seedDocument(t, ctx, pool, "SES-only cutover")

	var ruleID string
	must(t, pool.QueryRow(ctx,
		`INSERT INTO eidas_routing_rules
		 (org_id, name, predicate_json, required_tier, reason, active)
		 SELECT org_id, 'legacy AES', '{"field":"amount","op":">=","value":1}'::jsonb,
		        'AES', 'legacy seeded rule', true
		 FROM documents WHERE id = $1 RETURNING id::text`, docID,
	).Scan(&ruleID), "seed active legacy AES rule")
	err := mdb.RunMigrationsUpTo(migConn, 58)
	if err == nil || !strings.Contains(err.Error(), "owner deactivation") {
		t.Fatalf("migration 00058 with active AES rule = %v, want owner-deactivation failure", err)
	}

	_, err = pool.Exec(ctx, `UPDATE eidas_routing_rules SET active = false WHERE id = $1::uuid`, ruleID)
	must(t, err, "explicitly deactivate legacy rule")
	_, err = pool.Exec(ctx, `UPDATE documents SET routing_tier = 'QES' WHERE id = $1`, docID)
	must(t, err, "seed legacy higher-tier draft")
	err = mdb.RunMigrationsUpTo(migConn, 58)
	if err == nil || !strings.Contains(err.Error(), "owner reset") {
		t.Fatalf("migration 00058 with QES draft = %v, want owner-reset failure", err)
	}

	_, err = pool.Exec(ctx, `UPDATE documents SET routing_tier = 'SES' WHERE id = $1`, docID)
	must(t, err, "explicitly reset draft to SES")
	must(t, mdb.RunMigrationsUpTo(migConn, 58), "retry SES-only migration after explicit remediation")

	if _, err := pool.Exec(ctx, `UPDATE eidas_routing_rules SET active = true WHERE id = $1::uuid`, ruleID); err == nil {
		t.Fatal("database constraint allowed an active AES rule after SES-only cutover")
	}
	if _, err := pool.Exec(ctx, `UPDATE documents SET routing_tier = 'AES' WHERE id = $1`, docID); err == nil {
		t.Fatal("database constraint allowed an AES draft after SES-only cutover")
	}
	_, err = pool.Exec(ctx, `UPDATE documents SET status = 'completed', routing_tier = 'QES' WHERE id = $1`, docID)
	must(t, err, "preserve terminal historical higher-tier label")
}
