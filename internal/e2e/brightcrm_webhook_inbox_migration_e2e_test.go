// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package e2e

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	mdb "github.com/bright-interaction/hash/internal/db"
)

func TestBrightCRMWebhookInboxMigrationRollbackGuardE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	migConn := stdlibConn(t, pool)
	defer migConn.Close()

	must(t, mdb.RunMigrationsUpTo(migConn, 61), "migrate BrightCRM inbox scratch database to version 61")
	assertBrightCRMInboxSchema(t, ctx, pool, false)
	must(t, mdb.RunMigrationsUpTo(migConn, 62), "apply durable BrightCRM inbox migration")
	assertBrightCRMInboxSchema(t, ctx, pool, true)

	goose.SetBaseFS(nil)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	// A deployment rehearsal with no accepted delivery remains reversible.
	must(t, goose.DownTo(migConn, "../db/migrations", 61), "roll back empty BrightCRM inbox migration")
	assertAppliedMigrationVersion(t, ctx, pool, 61)
	assertBrightCRMInboxSchema(t, ctx, pool, false)
	must(t, mdb.RunMigrationsUpTo(migConn, 62), "re-apply durable BrightCRM inbox migration")
	// RunMigrationsUpTo restores the embedded migration FS. The explicit local
	// rollback below must reset Goose just like the first rehearsal did.
	goose.SetBaseFS(nil)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}

	// Even a zero-tenant event is a committed replay claim. Dropping it would
	// turn a late retry into a new delivery, so rollback must fail atomically.
	_, err := pool.Exec(ctx, `INSERT INTO brightcrm_webhook_receipts
		(delivery_correlation, payload_correlation, org_ids)
		VALUES (repeat('a', 64), repeat('b', 64), '{}'::uuid[])`)
	must(t, err, "insert committed zero-tenant BrightCRM receipt")
	err = goose.DownTo(migConn, "../db/migrations", 61)
	if err == nil || !strings.Contains(err.Error(), "preserve replay protection") {
		t.Fatalf("migration 00062 down after durable receipt = %v, want replay-protection refusal", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 62)
	assertBrightCRMInboxSchema(t, ctx, pool, true)
}

func assertBrightCRMInboxSchema(t *testing.T, ctx context.Context, pool *pgxpool.Pool, want bool) {
	t.Helper()
	var tableExists, lookupIndexExists bool
	if err := pool.QueryRow(ctx, `SELECT
		to_regclass('public.brightcrm_webhook_receipts') IS NOT NULL,
		to_regclass('public.idx_var_bindings_source_lookup') IS NOT NULL`).Scan(
		&tableExists, &lookupIndexExists,
	); err != nil {
		t.Fatalf("inspect BrightCRM inbox schema: %v", err)
	}
	if tableExists != want || lookupIndexExists != want {
		t.Fatalf("BrightCRM inbox schema table/index = %v/%v, want %v/%v", tableExists, lookupIndexExists, want, want)
	}
}
