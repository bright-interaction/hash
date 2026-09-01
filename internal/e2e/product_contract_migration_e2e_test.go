// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package e2e

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	mdb "github.com/bright-interaction/hash/internal/db"
)

// Contract variables are contractual input, so migration 00054 may normalize
// only the unambiguous legacy empty-array default. Every other invalid shape
// must stop the cutover atomically until the controller remediates it.
func TestContractVariableShapeMigrationFailsClosedAndConstrainsEveryCopy(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	migConn := stdlibConn(t, pool)
	defer migConn.Close()

	must(t, mdb.RunMigrationsUpTo(migConn, 53), "migrate scratch database to pre-variable-shape version 53")
	docID := seedDocument(t, ctx, pool, "contract-variable cutover")

	var invalidTemplateID, safeTemplateID, versionID uuid.UUID
	must(t, pool.QueryRow(ctx,
		`INSERT INTO templates
		 (org_id, name, source_kind, blocks_json, variables_json, created_by)
		 SELECT org_id, 'invalid variables', 'blocks', '{"version":1,"blocks":[]}'::jsonb,
		        '{"amount":12}'::jsonb, sender_id
		 FROM documents WHERE id = $1 RETURNING id`, docID,
	).Scan(&invalidTemplateID), "seed invalid template variables")
	must(t, pool.QueryRow(ctx,
		`INSERT INTO templates
		 (org_id, name, source_kind, blocks_json, variables_json, created_by)
		 SELECT org_id, 'safe empty variables', 'blocks', '{"version":1,"blocks":[]}'::jsonb,
		        '[]'::jsonb, sender_id
		 FROM documents WHERE id = $1 RETURNING id`, docID,
	).Scan(&safeTemplateID), "seed unambiguous empty-array template variables")
	_, err := pool.Exec(ctx, `UPDATE documents SET variables_json = '{"bad key":"Ada"}'::jsonb WHERE id = $1`, docID)
	must(t, err, "seed invalid document variables")
	must(t, pool.QueryRow(ctx,
		`INSERT INTO document_versions
		 (document_id, org_id, version_no, block_tree_json, variables_json, name, source_kind, created_by)
		 SELECT id, org_id, 1, blocks_json, '[1]'::jsonb, name, source_kind, sender_id
		 FROM documents WHERE id = $1 RETURNING id`, docID,
	).Scan(&versionID), "seed invalid document-version variables")

	assertMigration54Refusal := func(want string) {
		t.Helper()
		err := mdb.RunMigrationsUpTo(migConn, 54)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("migration 00054 error = %v, want refusal containing %q", err, want)
		}
		assertAppliedMigrationVersion(t, ctx, pool, 53)
	}

	assertMigration54Refusal("invalid template variables_json rows")
	var validatorRolledBack, safeArrayRolledBack bool
	must(t, pool.QueryRow(ctx,
		`SELECT to_regprocedure('hash_contract_variables_valid(jsonb)') IS NULL`,
	).Scan(&validatorRolledBack), "inspect validator after failed migration")
	if !validatorRolledBack {
		t.Fatal("failed migration 00054 left its validator function behind")
	}
	must(t, pool.QueryRow(ctx,
		`SELECT variables_json = '[]'::jsonb FROM templates WHERE id = $1`, safeTemplateID,
	).Scan(&safeArrayRolledBack), "inspect safe normalization rollback")
	if !safeArrayRolledBack {
		t.Fatal("failed migration 00054 partially committed safe empty-array normalization")
	}

	_, err = pool.Exec(ctx,
		`UPDATE templates SET variables_json = '{"amount":"12"}'::jsonb WHERE id = $1`, invalidTemplateID)
	must(t, err, "remediate invalid template variables")
	assertMigration54Refusal("invalid document variables_json rows")

	_, err = pool.Exec(ctx,
		`UPDATE documents SET variables_json = '{"customer.name":"Ada"}'::jsonb WHERE id = $1`, docID)
	must(t, err, "remediate invalid document variables")
	assertMigration54Refusal("invalid document-version variables_json rows")

	_, err = pool.Exec(ctx,
		`UPDATE document_versions SET variables_json = '{"version_key":"value"}'::jsonb WHERE id = $1`, versionID)
	must(t, err, "remediate invalid document-version variables")
	must(t, mdb.RunMigrationsUpTo(migConn, 54), "retry variable-shape migration after explicit remediation")
	assertAppliedMigrationVersion(t, ctx, pool, 54)

	var constraintCount int
	must(t, pool.QueryRow(ctx,
		`SELECT count(*)
		 FROM pg_constraint
		 WHERE conname IN (
		   'templates_contract_variables_shape',
		   'documents_contract_variables_shape',
		   'document_versions_contract_variables_shape'
		 )`,
	).Scan(&constraintCount), "inspect variable-shape constraints")
	if constraintCount != 3 {
		t.Fatalf("migration 00054 installed %d variable-shape constraints, want 3", constraintCount)
	}

	var safeNormalized, defaultNormalized bool
	must(t, pool.QueryRow(ctx,
		`SELECT variables_json = '{}'::jsonb FROM templates WHERE id = $1`, safeTemplateID,
	).Scan(&safeNormalized), "inspect safe empty-array normalization")
	if !safeNormalized {
		t.Fatal("migration 00054 did not normalize the unambiguous empty-array template value")
	}
	must(t, pool.QueryRow(ctx,
		`INSERT INTO templates (org_id, name, source_kind, blocks_json, created_by)
		 SELECT org_id, 'post-cutover default', 'blocks', '{"version":1,"blocks":[]}'::jsonb, sender_id
		 FROM documents WHERE id = $1
		 RETURNING variables_json = '{}'::jsonb`, docID,
	).Scan(&defaultNormalized), "inspect post-cutover template default")
	if !defaultNormalized {
		t.Fatal("migration 00054 left the template default in the legacy array shape")
	}

	if _, err := pool.Exec(ctx, `UPDATE templates SET variables_json = '[]'::jsonb WHERE id = $1`, invalidTemplateID); err == nil {
		t.Fatal("template constraint accepted an array after migration 00054")
	}
	if _, err := pool.Exec(ctx, `UPDATE documents SET variables_json = '{"amount":12}'::jsonb WHERE id = $1`, docID); err == nil {
		t.Fatal("document constraint accepted a non-string value after migration 00054")
	}
	if _, err := pool.Exec(ctx, `UPDATE document_versions SET variables_json = '{"bad key":"x"}'::jsonb WHERE id = $1`, versionID); err == nil {
		t.Fatal("document-version constraint accepted an invalid key after migration 00054")
	}
}

// Migration 00056 cannot safely invent a controller identity for an existing
// confirmation. It must refuse that state, then require every new confirmation
// to carry a non-empty contract-only disclosure snapshot that remains stable
// if the organization record later changes.
func TestFrozenControllerDisclosureMigrationFailsClosedAndFreezesSnapshot(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	migConn := stdlibConn(t, pool)
	defer migConn.Close()

	must(t, mdb.RunMigrationsUpTo(migConn, 55), "migrate scratch database to pre-controller-snapshot version 55")
	docID := seedDocument(t, ctx, pool, "controller-disclosure cutover")
	_, err := pool.Exec(ctx,
		`INSERT INTO document_lawful_basis_confirmations
		 (document_id, org_id, lawful_basis, confirmed_by, via)
		 SELECT id, org_id, 'legal_obligation', sender_id, 'test'
		 FROM documents WHERE id = $1`, docID)
	must(t, err, "seed pre-snapshot lawful-basis confirmation")

	err = mdb.RunMigrationsUpTo(migConn, 56)
	if err == nil || !strings.Contains(err.Error(), "pre-snapshot lawful-basis confirmations") {
		t.Fatalf("migration 00056 with a pre-snapshot confirmation = %v, want explicit refusal", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 55)

	var snapshotColumnCount int
	must(t, pool.QueryRow(ctx,
		`SELECT count(*)
		 FROM information_schema.columns
		 WHERE table_schema = 'public'
		   AND table_name = 'document_lawful_basis_confirmations'
		   AND column_name IN ('controller_name', 'controller_contact')`,
	).Scan(&snapshotColumnCount), "inspect failed controller-snapshot migration")
	if snapshotColumnCount != 0 {
		t.Fatalf("failed migration 00056 left %d snapshot columns behind", snapshotColumnCount)
	}
	var legacyBasis string
	must(t, pool.QueryRow(ctx,
		`SELECT lawful_basis FROM document_lawful_basis_confirmations WHERE document_id = $1`, docID,
	).Scan(&legacyBasis), "inspect legacy confirmation after failed migration")
	if legacyBasis != "legal_obligation" {
		t.Fatalf("failed migration 00056 changed legacy confirmation basis to %q", legacyBasis)
	}

	_, err = pool.Exec(ctx, `DELETE FROM document_lawful_basis_confirmations WHERE document_id = $1`, docID)
	must(t, err, "apply explicit pre-snapshot confirmation remediation")
	must(t, mdb.RunMigrationsUpTo(migConn, 56), "retry controller-snapshot migration after explicit remediation")
	assertAppliedMigrationVersion(t, ctx, pool, 56)

	must(t, pool.QueryRow(ctx,
		`SELECT count(*)
		 FROM information_schema.columns
		 WHERE table_schema = 'public'
		   AND table_name = 'document_lawful_basis_confirmations'
		   AND column_name IN ('controller_name', 'controller_contact')
		   AND is_nullable = 'NO'`,
	).Scan(&snapshotColumnCount), "inspect required controller-snapshot columns")
	if snapshotColumnCount != 2 {
		t.Fatalf("migration 00056 installed %d required snapshot columns, want 2", snapshotColumnCount)
	}

	const frozenName = "Sales Partner Controller AB"
	const frozenContact = "privacy@sales-partner.example"
	_, err = pool.Exec(ctx,
		`INSERT INTO document_lawful_basis_confirmations
		 (document_id, org_id, lawful_basis, confirmed_by, via, controller_name, controller_contact)
		 SELECT id, org_id, 'contract', sender_id, 'test', $2, $3
		 FROM documents WHERE id = $1`, docID, frozenName, frozenContact)
	must(t, err, "insert post-cutover frozen controller snapshot")
	_, err = pool.Exec(ctx,
		`UPDATE orgs SET name = 'Renamed organization after confirmation'
		 WHERE id = (SELECT org_id FROM documents WHERE id = $1)`, docID)
	must(t, err, "rename organization after controller snapshot")

	assertFrozenControllerSnapshot(t, ctx, pool, docID, frozenName, frozenContact)

	missingSnapshotDocID := seedDocument(t, ctx, pool, "missing controller snapshot")
	if _, err := pool.Exec(ctx,
		`INSERT INTO document_lawful_basis_confirmations
		 (document_id, org_id, lawful_basis, confirmed_by, via)
		 SELECT id, org_id, 'contract', sender_id, 'test'
		 FROM documents WHERE id = $1`, missingSnapshotDocID); err == nil {
		t.Fatal("post-cutover confirmation accepted missing controller snapshot fields")
	}
	if _, err := pool.Exec(ctx,
		`UPDATE document_lawful_basis_confirmations SET lawful_basis = 'consent' WHERE document_id = $1`, docID); err == nil {
		t.Fatal("post-cutover confirmation accepted a basis without product evidence")
	}
	if _, err := pool.Exec(ctx,
		`UPDATE document_lawful_basis_confirmations SET controller_name = ' ' WHERE document_id = $1`, docID); err == nil {
		t.Fatal("post-cutover confirmation accepted a blank controller name")
	}
	if _, err := pool.Exec(ctx,
		`UPDATE document_lawful_basis_confirmations SET controller_contact = ' ' WHERE document_id = $1`, docID); err == nil {
		t.Fatal("post-cutover confirmation accepted a blank controller contact")
	}

	assertFrozenControllerSnapshot(t, ctx, pool, docID, frozenName, frozenContact)
}

func assertAppliedMigrationVersion(t *testing.T, ctx context.Context, pool *pgxpool.Pool, want int64) {
	t.Helper()
	var got int64
	if err := pool.QueryRow(ctx,
		`SELECT max(version_id) FROM goose_db_version WHERE is_applied`,
	).Scan(&got); err != nil {
		t.Fatalf("read applied migration version: %v", err)
	}
	if got != want {
		t.Fatalf("applied migration version = %d, want %d", got, want)
	}
}

func assertFrozenControllerSnapshot(t *testing.T, ctx context.Context, pool *pgxpool.Pool, documentID uuid.UUID, wantName, wantContact string) {
	t.Helper()
	var gotName, gotContact, gotBasis string
	if err := pool.QueryRow(ctx,
		`SELECT controller_name, controller_contact, lawful_basis
		 FROM document_lawful_basis_confirmations
		 WHERE document_id = $1`, documentID,
	).Scan(&gotName, &gotContact, &gotBasis); err != nil {
		t.Fatalf("read frozen controller snapshot: %v", err)
	}
	if gotName != wantName || gotContact != wantContact || gotBasis != "contract" {
		t.Fatalf("frozen controller snapshot = (%q, %q, %q), want (%q, %q, contract)",
			gotName, gotContact, gotBasis, wantName, wantContact)
	}
}
