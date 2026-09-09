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
	"github.com/pressly/goose/v3"

	mdb "github.com/bright-interaction/hash/internal/db"
)

func TestFrozenBrandingMigrationRefusesUnboundActiveDocumentE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	migConn := stdlibConn(t, pool)
	defer migConn.Close()
	must(t, mdb.RunMigrationsUpTo(migConn, 64), "migrate branding cutover fixture to version 64")

	docID := seedDocument(t, ctx, pool, "frozen branding unbound cutover")
	_, err := pool.Exec(ctx, `UPDATE documents SET status='voided' WHERE id=$1`, docID)
	must(t, err, "seed legacy non-draft document without a snapshot")
	err = mdb.RunMigrationsUpTo(migConn, 65)
	if err == nil || !strings.Contains(err.Error(), "complete, valid, logo-free snapshot") {
		t.Fatalf("migration 00065 with unbound active document = %v, want explicit remediation hold", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 64)

	_, err = pool.Exec(ctx, completeFrozenBrandingFixtureSQL, docID)
	must(t, err, "seed complete legacy branding snapshot")
	for _, invalid := range []struct {
		name  string
		query string
	}{
		{name: "invalid color", query: `UPDATE document_branding_override SET primary_hex='not-a-color' WHERE document_id=$1`},
		{name: "blank font", query: `UPDATE document_branding_override SET primary_hex='#0F172A', font_body=' ' WHERE document_id=$1`},
		{name: "tab and newline font", query: `UPDATE document_branding_override SET font_body=E'\t\n' WHERE document_id=$1`},
		{name: "noncanonical font", query: `UPDATE document_branding_override SET font_body=' Inter' WHERE document_id=$1`},
		{name: "unsafe font punctuation", query: `UPDATE document_branding_override SET font_body='Inter;}*{display:none}' WHERE document_id=$1`},
		{name: "oversized font", query: `UPDATE document_branding_override SET font_body=repeat('A', 257) WHERE document_id=$1`},
		{name: "document logo", query: `UPDATE document_branding_override SET font_body='Inter', logo_url='https://example.invalid/logo.png' WHERE document_id=$1`},
	} {
		_, err = pool.Exec(ctx, invalid.query, docID)
		must(t, err, "seed "+invalid.name)
		err = mdb.RunMigrationsUpTo(migConn, 65)
		if err == nil || !strings.Contains(err.Error(), "complete, valid, logo-free snapshot") {
			t.Fatalf("migration 00065 with %s = %v, want exact frozen predicate refusal", invalid.name, err)
		}
		assertAppliedMigrationVersion(t, ctx, pool, 64)
	}

	_, err = pool.Exec(ctx, `UPDATE document_branding_override SET logo_url='' WHERE document_id=$1`, docID)
	must(t, err, "clear unsupported document logo")
	_, err = pool.Exec(ctx, `INSERT INTO org_branding (org_id, logo_url)
		SELECT org_id, 'https://example.invalid/org-logo.png' FROM documents WHERE id=$1`, docID)
	must(t, err, "seed unsupported organization logo")
	err = mdb.RunMigrationsUpTo(migConn, 65)
	if err == nil || !strings.Contains(err.Error(), "every organization and document logo to be empty") {
		t.Fatalf("migration 00065 with organization logo = %v, want global logo refusal", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 64)
	_, err = pool.Exec(ctx, `UPDATE org_branding SET logo_url='' WHERE org_id=(SELECT org_id FROM documents WHERE id=$1)`, docID)
	must(t, err, "clear unsupported organization logo")

	draftLogoID := seedDocument(t, ctx, pool, "frozen branding draft logo cutover")
	_, err = pool.Exec(ctx, completeFrozenBrandingFixtureSQL, draftLogoID)
	must(t, err, "seed draft branding snapshot")
	_, err = pool.Exec(ctx, `UPDATE document_branding_override SET logo_url='/branding/logo/legacy.png' WHERE document_id=$1`, draftLogoID)
	must(t, err, "seed unsupported draft document logo")
	err = mdb.RunMigrationsUpTo(migConn, 65)
	if err == nil || !strings.Contains(err.Error(), "every organization and document logo to be empty") {
		t.Fatalf("migration 00065 with draft document logo = %v, want global logo refusal", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 64)
	_, err = pool.Exec(ctx, `UPDATE document_branding_override SET logo_url='' WHERE document_id=$1`, draftLogoID)
	must(t, err, "clear unsupported draft document logo")
	must(t, mdb.RunMigrationsUpTo(migConn, 65), "apply branding guard after exact-predicate remediation")
	assertAppliedMigrationVersion(t, ctx, pool, 65)

	// The cutover inventory is not enough: an old writer can create a new
	// draft after migration and try to leave draft without running Send's
	// snapshot materialization. The document trigger must reject that path.
	postCutoverID := seedDocument(t, ctx, pool, "post-cutover draft without frozen branding")
	if _, err := pool.Exec(ctx, `UPDATE documents SET status='sealing' WHERE id=$1`, postCutoverID); err == nil ||
		!strings.Contains(err.Error(), "cannot leave draft") {
		t.Fatalf("post-cutover draft exit without snapshot = %v, want database refusal", err)
	}
	_, err = pool.Exec(ctx, completeFrozenBrandingFixtureSQL, postCutoverID)
	must(t, err, "seed post-cutover frozen branding")
	_, err = pool.Exec(ctx, `UPDATE document_branding_override SET font_body=E'\t\n' WHERE document_id=$1`, postCutoverID)
	must(t, err, "seed invalid editable post-cutover branding")
	if _, err := pool.Exec(ctx, `UPDATE documents SET status='sealing' WHERE id=$1`, postCutoverID); err == nil ||
		!strings.Contains(err.Error(), "cannot leave draft") {
		t.Fatalf("post-cutover draft exit with whitespace font = %v, want database refusal", err)
	}
	_, err = pool.Exec(ctx, `UPDATE document_branding_override SET font_body='Inter' WHERE document_id=$1`, postCutoverID)
	must(t, err, "repair post-cutover branding")
	_, err = pool.Exec(ctx, `UPDATE documents SET status='sealing' WHERE id=$1`, postCutoverID)
	must(t, err, "leave draft with a complete canonical snapshot")
}

func TestFrozenBrandingSnapshotIsImmutableAfterSendTransitionE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	migConn := stdlibConn(t, pool)
	defer migConn.Close()
	must(t, mdb.RunMigrations(migConn), "migrate frozen branding fixture to latest")

	docID := seedDocument(t, ctx, pool, "frozen branding send transition")
	var orgID uuid.UUID
	must(t, pool.QueryRow(ctx, `SELECT org_id FROM documents WHERE id=$1`, docID).Scan(&orgID), "load document organization")
	_, err := pool.Exec(ctx, completeFrozenBrandingFixtureSQL, docID)
	must(t, err, "seed editable draft branding")

	// Model Send's atomic critical section: lock the draft, materialize every
	// effective branding field, and leave draft before committing.
	tx, err := pool.Begin(ctx)
	must(t, err, "begin send-like transaction")
	defer func() { _ = tx.Rollback(context.Background()) }()
	var lockedID uuid.UUID
	must(t, tx.QueryRow(ctx, `SELECT id FROM documents WHERE id=$1 AND org_id=$2 FOR UPDATE`, docID, orgID).Scan(&lockedID), "lock send document")
	_, err = tx.Exec(ctx, completeFrozenBrandingFixtureSQL, docID)
	must(t, err, "freeze complete document branding")
	_, err = tx.Exec(ctx, `UPDATE documents SET status='sealing' WHERE id=$1`, docID)
	must(t, err, "begin send sealing")

	// A branding write that races this still-uncommitted Send must wait on the
	// document lock instead of observing the old draft state. A short database
	// lock timeout gives deterministic proof of that serialization boundary.
	probeTx, err := pool.Begin(ctx)
	must(t, err, "begin concurrent branding probe")
	_, err = probeTx.Exec(ctx, `SET LOCAL lock_timeout='100ms'`)
	must(t, err, "bound concurrent branding probe")
	_, err = probeTx.Exec(ctx,
		`UPDATE document_branding_override SET accent_hex='#FF0000' WHERE document_id=$1`, docID)
	if err == nil || !strings.Contains(err.Error(), "lock timeout") {
		_ = probeTx.Rollback(ctx)
		t.Fatalf("branding mutation racing Send = %v, want document-lock serialization", err)
	}
	_ = probeTx.Rollback(ctx)
	must(t, tx.Commit(ctx), "commit send-like transaction")

	if _, err := pool.Exec(ctx,
		`UPDATE document_branding_override SET accent_hex='#FF0000' WHERE document_id=$1`, docID,
	); err == nil || !strings.Contains(err.Error(), "immutable outside draft") {
		t.Fatalf("post-send branding update = %v, want immutable-trigger refusal", err)
	}
	if _, err := pool.Exec(ctx,
		`DELETE FROM document_branding_override WHERE document_id=$1`, docID,
	); err == nil || !strings.Contains(err.Error(), "immutable outside draft") {
		t.Fatalf("post-send branding delete = %v, want immutable-trigger refusal", err)
	}

	var accent string
	must(t, pool.QueryRow(ctx,
		`SELECT accent_hex FROM document_branding_override WHERE document_id=$1`, docID,
	).Scan(&accent), "read frozen branding after refused mutations")
	if accent != "#3B82F6" {
		t.Fatalf("frozen accent = %q, want original snapshot", accent)
	}

	// The guard must preserve the application's existing hard-purge path for a
	// draft. PostgreSQL's FK cascade reaches the child trigger after deleting
	// the parent row; that narrow no-parent DELETE path is intentionally allowed.
	purgeID := seedDocument(t, ctx, pool, "frozen branding draft purge")
	_, err = pool.Exec(ctx, completeFrozenBrandingFixtureSQL, purgeID)
	must(t, err, "seed purgeable draft branding")
	_, err = pool.Exec(ctx, `DELETE FROM documents WHERE id=$1 AND status='draft'`, purgeID)
	must(t, err, "purge draft with branding snapshot")
	var remaining int
	must(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM document_branding_override WHERE document_id=$1`, purgeID,
	).Scan(&remaining), "count branding after draft purge")
	if remaining != 0 {
		t.Fatalf("draft purge left %d branding snapshots", remaining)
	}

	// Removing the guard while any ceremony is outside draft would reopen the
	// mutation path. The down migration is therefore deliberately one-way once
	// such state exists, but remains mechanically reversible on a draft-only DB.
	goose.SetBaseFS(nil)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	err = goose.DownTo(migConn, "../db/migrations", 64)
	if err == nil || !strings.Contains(err.Error(), "after a document has left draft") {
		t.Fatalf("migration 00065 rollback with sealing document = %v, want refusal", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 65)
	_, err = pool.Exec(ctx, `UPDATE documents SET status='draft' WHERE id=$1`, docID)
	must(t, err, "return fixture to draft for safe rollback")
	must(t, goose.DownTo(migConn, "../db/migrations", 64), "roll back branding guard on draft-only database")
	assertAppliedMigrationVersion(t, ctx, pool, 64)

	// A clean down/re-up is mechanically safe, but a durable send marker must
	// make the second Down one-way even when current document state is draft.
	must(t, mdb.RunMigrationsUpTo(migConn, 65), "reapply branding guard after clean rollback")
	_, err = pool.Exec(ctx, `UPDATE documents SET status='sealing' WHERE id=$1`, docID)
	must(t, err, "begin durable send-history fixture")
	_, err = pool.Exec(ctx, `INSERT INTO events (
		org_id, document_id, kind, payload_json, payload_hashed, row_hash
	) VALUES (
		$1, $2, 'document.sent',
		jsonb_build_object(
			'required_notice_schema', 'hash-a13-2026-08-31',
			'required_notice_sent_at', '2026-09-09T05:00:00Z'
		),
		convert_to(jsonb_build_object(
			'required_notice_schema', 'hash-a13-2026-08-31',
			'required_notice_sent_at', '2026-09-09T05:00:00Z'
		)::text, 'UTF8'),
		decode(repeat('00', 32), 'hex')
	)`, orgID, docID)
	must(t, err, "seed chain-shaped persistent send marker")
	_, err = pool.Exec(ctx, `UPDATE documents SET
		status='sent', sent_at='2026-09-09T05:00:00Z'::timestamptz,
		article13_notice_epoch_at='2026-09-09T05:00:00Z'::timestamptz,
		article13_notice_schema='hash-a13-2026-08-31',
		article13_notice_epoch_v61_committed=TRUE
		WHERE id=$1`, docID)
	must(t, err, "commit durable send-history fixture")
	_, err = pool.Exec(ctx, `UPDATE documents SET status='changes_requested' WHERE id=$1`, docID)
	must(t, err, "pause durable send-history fixture")
	_, err = pool.Exec(ctx, `UPDATE documents SET status='draft', sent_at=NULL WHERE id=$1`, docID)
	must(t, err, "reopen durable send-history fixture to draft")
	var committed bool
	must(t, pool.QueryRow(ctx, `SELECT article13_notice_epoch_v61_committed
		FROM documents WHERE id=$1 AND status='draft'`, docID).Scan(&committed), "read reopened ceremony provenance")
	if !committed {
		t.Fatal("reopened draft lost its durable Article 13 ceremony commitment")
	}
	goose.SetBaseFS(nil)
	err = goose.DownTo(migConn, "../db/migrations", 64)
	if err == nil || !strings.Contains(err.Error(), "committed a send ceremony") {
		t.Fatalf("migration 00065 rollback after reopened send ceremony = %v, want persistent-history refusal", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 65)
}
