// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package e2e

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	"github.com/bright-interaction/hash/internal/article13"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/storage"
)

// Migration 00060 must not invent or repeatedly extend Object Lock deadlines.
// A pre-control send cannot reconstruct the exact sent_at that future evidence
// will claim, so the cutover refuses it rather than inventing an epoch. Once
// drained, the schema enforces immutable deadlines and exact document/intent
// identity for every new lifecycle operation.
func TestRetentionDeadlineMigrationCutoverAndRetryGuardsE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	migConn := stdlibConn(t, pool)
	defer migConn.Close()

	// Keep one true pre-00059 terminal row in the fixture. Migration 00059
	// recovers its exact historical completion instant; 00060 must not fabricate
	// a retention commitment for evidence already written by an older binary.
	must(t, mdb.RunMigrationsUpTo(migConn, 58), "migrate scratch database to pre-completion version 58")
	historicalID := seedDocument(t, ctx, pool, "retention historical completion")
	historicalCompletedAt := time.Date(2026, time.August, 29, 9, 8, 7, 0, time.UTC)
	_, err := pool.Exec(ctx,
		`UPDATE documents SET status = 'completed', completed_at = $2 WHERE id = $1`,
		historicalID, historicalCompletedAt)
	must(t, err, "seed historical completed document")
	must(t, mdb.RunMigrationsUpTo(migConn, 59), "migrate scratch database to completion version 59")

	// Although 00059 itself required a drained inventory, an old application
	// instance could start another finalization before 00060 is applied. Refuse
	// that race atomically and leave no partial columns behind.
	cutoverID := seedDocument(t, ctx, pool, "retention cutover race")
	cutoverAt := time.Date(2026, time.August, 30, 10, 11, 12, 0, time.UTC)
	_, err = pool.Exec(ctx,
		`UPDATE documents
		 SET status = 'finalizing', completion_effective_at = $2
		 WHERE id = $1`, cutoverID, cutoverAt)
	must(t, err, "seed post-00059 in-flight finalization")
	err = mdb.RunMigrationsUpTo(migConn, 60)
	if err == nil || !strings.Contains(err.Error(), "in-flight finalization") {
		t.Fatalf("migration 00060 with active finalization = %v, want explicit inventory refusal", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 59)
	assertRetentionDeadlineColumns(t, ctx, pool, false)
	_, err = pool.Exec(ctx, `DELETE FROM documents WHERE id = $1`, cutoverID)
	must(t, err, "drain raced finalization inventory")
	post59CompletedID := seedDocument(t, ctx, pool, "retention post-00059 completion race")
	_, err = pool.Exec(ctx,
		`UPDATE documents
		 SET status = 'completed', completion_effective_at = $2,
		     completion_effective_at_bound = TRUE, completed_at = $2
		 WHERE id = $1`, post59CompletedID, cutoverAt)
	must(t, err, "seed post-00059 completed document without a recoverable retention target")
	err = mdb.RunMigrationsUpTo(migConn, 60)
	if err == nil || !strings.Contains(err.Error(), "post-00059 completion") {
		t.Fatalf("migration 00060 with post-00059 completion = %v, want explicit unrecoverable-inventory refusal", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 59)
	assertRetentionDeadlineColumns(t, ctx, pool, false)
	_, err = pool.Exec(ctx, `DELETE FROM documents WHERE id = $1`, post59CompletedID)
	must(t, err, "drain post-00059 completion inventory")

	// No pre-control send intent has an authoritative future sent_at. Even a row
	// with a retention-start marker is unrecoverable: created_at/start time is not
	// the legal ceremony epoch. The operator must explicitly drain it first.
	legacySendID := seedDocument(t, ctx, pool, "retention legacy send")
	legacyStartedAt := time.Date(2026, time.August, 30, 12, 13, 14, 987654000, time.UTC)
	_, err = pool.Exec(ctx, `UPDATE documents SET status = 'sealing' WHERE id = $1`, legacySendID)
	must(t, err, "seed legacy sealing document")
	_, err = pool.Exec(ctx,
		`INSERT INTO send_sealing_intents
		 (document_id, org_id, retention_started_at, created_at, updated_at)
		 SELECT id, org_id, $2::timestamptz, $2::timestamptz - interval '1 minute', $2::timestamptz
		 FROM documents WHERE id = $1`, legacySendID, legacyStartedAt)
	must(t, err, "seed legacy started send retention")
	err = mdb.RunMigrationsUpTo(migConn, 60)
	if err == nil || !strings.Contains(err.Error(), "pre-control send sealing") {
		t.Fatalf("migration 00060 with legacy send intent = %v, want explicit unrecoverable-inventory refusal", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 59)
	assertRetentionDeadlineColumns(t, ctx, pool, false)
	_, err = pool.Exec(ctx, `DELETE FROM send_sealing_intents WHERE document_id = $1`, legacySendID)
	must(t, err, "drain legacy send intent")
	_, err = pool.Exec(ctx, `DELETE FROM documents WHERE id = $1`, legacySendID)
	must(t, err, "drain legacy sealing document")
	must(t, mdb.RunMigrationsUpTo(migConn, 60), "apply durable retention deadline migration")
	assertAppliedMigrationVersion(t, ctx, pool, 60)
	assertRetentionDeadlineColumns(t, ctx, pool, true)
	leapAnchor := time.Date(2024, time.February, 29, 23, 59, 59, 123456000, time.FixedZone("migration-test", 2*60*60))
	var databaseLeapDeadline time.Time
	must(t, pool.QueryRow(ctx,
		`SELECT hash_evidence_retain_until($1, $2)`, leapAnchor, article13.RetentionYearsV1,
	).Scan(&databaseLeapDeadline), "evaluate database retention calendar helper")
	wantLeapDeadline := storage.EvidenceRetentionDeadline(leapAnchor, article13.RetentionYearsV1)
	if !databaseLeapDeadline.Equal(wantLeapDeadline) {
		t.Fatalf("database leap deadline = %s, want application-identical %s", databaseLeapDeadline, wantLeapDeadline)
	}

	var historicalRetainUntil *time.Time
	must(t, pool.QueryRow(ctx,
		`SELECT finalization_retain_until FROM documents WHERE id = $1`, historicalID,
	).Scan(&historicalRetainUntil), "read historical retention deadline")
	if historicalRetainUntil != nil {
		t.Fatalf("historical completion received fabricated retention deadline %s", *historicalRetainUntil)
	}
	missingFinalizingID := seedDocument(t, ctx, pool, "retention missing finalizing deadline")
	if _, err := pool.Exec(ctx,
		`UPDATE documents
		 SET status = 'finalizing', sent_at = $2 - interval '1 second', completion_effective_at = $2,
		     completion_effective_at_bound = TRUE
		 WHERE id = $1`, missingFinalizingID, cutoverAt); err == nil {
		t.Fatal("bound finalizing document accepted a NULL finalization retention deadline")
	}
	missingCompletedID := seedDocument(t, ctx, pool, "retention missing completed deadline")
	if _, err := pool.Exec(ctx,
		`UPDATE documents
		 SET status = 'completed', sent_at = $2 - interval '1 second', completion_effective_at = $2,
		     completion_effective_at_bound = TRUE, completed_at = $2
		 WHERE id = $1`, missingCompletedID, cutoverAt); err == nil {
		t.Fatal("bound completed document accepted a NULL finalization retention deadline")
	}
	misorderedID := seedDocument(t, ctx, pool, "retention misordered completion epoch")
	if _, err := pool.Exec(ctx,
		`UPDATE documents
		 SET status = 'finalizing', sent_at = $2, completion_effective_at = $2,
		     completion_effective_at_bound = TRUE,
		     finalization_retain_until = hash_evidence_retain_until($2, $3)
		 WHERE id = $1`, misorderedID, cutoverAt, article13.RetentionYearsV1); err == nil {
		t.Fatal("bound finalization accepted a completion epoch that did not follow sent_at")
	}

	// The document commitment is the authoritative finalization deadline. The
	// composite FK rejects an intent carrying any other value, and both copies
	// reject rewrites after the first successful insert.
	finalID := seedDocument(t, ctx, pool, "retention finalization identity")
	_, err = pool.Exec(ctx,
		`UPDATE documents
		 SET status = 'in_progress', sent_at = statement_timestamp() - interval '1 second'
		 WHERE id = $1`, finalID)
	must(t, err, "make finalization fixture active")
	var completionAt, wantFinalDeadline, lifecycleUpdatedAt time.Time
	must(t, pool.QueryRow(ctx,
		`WITH lifecycle_clock AS (SELECT statement_timestamp() AS effective_at)
		 UPDATE documents
		 SET status = 'finalizing',
		     completion_effective_at_bound = TRUE,
		     completion_effective_at = COALESCE(completion_effective_at, lifecycle_clock.effective_at),
		     finalization_retain_until = COALESCE(
		       finalization_retain_until,
		       hash_evidence_retain_until(COALESCE(completion_effective_at, lifecycle_clock.effective_at), $2)
		     ),
		     updated_at = lifecycle_clock.effective_at
		 FROM lifecycle_clock
		 WHERE id = $1 AND status = 'in_progress'
		 RETURNING completion_effective_at, finalization_retain_until, updated_at`,
		finalID, article13.RetentionYearsV1,
	).Scan(&completionAt, &wantFinalDeadline, &lifecycleUpdatedAt), "atomically claim finalization retention deadline")
	if want := storage.EvidenceRetentionDeadline(completionAt, article13.RetentionYearsV1); !wantFinalDeadline.Equal(want) {
		t.Fatalf("claimed finalization deadline = %s, want exact %s", wantFinalDeadline, want)
	}
	if !lifecycleUpdatedAt.Equal(completionAt) {
		t.Fatalf("finalization updated_at = %s, want claim epoch %s", lifecycleUpdatedAt, completionAt)
	}
	var retryCompletionAt, retryFinalDeadline time.Time
	must(t, pool.QueryRow(ctx,
		`SELECT completion_effective_at, finalization_retain_until FROM documents WHERE id = $1`, finalID,
	).Scan(&retryCompletionAt, &retryFinalDeadline), "reload retry-stable finalization commitment")
	if !retryCompletionAt.Equal(completionAt) || !retryFinalDeadline.Equal(wantFinalDeadline) {
		t.Fatalf("reloaded finalization commitment = %s/%s, want %s/%s", retryCompletionAt, retryFinalDeadline, completionAt, wantFinalDeadline)
	}

	insertFinalizationIntent := func(retainUntil time.Time) error {
		_, insertErr := pool.Exec(ctx,
			`INSERT INTO document_finalization_intents (
			 document_id, org_id, mode, completion_effective_at, retain_until,
			 final_pdf_key, final_pdf_sha256, final_pdf_version_id,
			 audit_cert_key, audit_cert_sha256, audit_cert_version_id,
			 audit_payload_key, audit_payload_sha256, audit_payload_version_id,
			 audit_signature_key, audit_signature_sha256, audit_signature_version_id
			)
			SELECT id, org_id, 'signature', $2, $3,
			 'org/' || org_id::text || '/documents/' || id::text || '/final-' || repeat('00', 32) || '.pdf', decode(repeat('00', 32), 'hex'), 'final-version',
			 'org/' || org_id::text || '/documents/' || id::text || '/audit-' || repeat('00', 32) || '.pdf', decode(repeat('00', 32), 'hex'), 'cert-version',
			 'org/' || org_id::text || '/documents/' || id::text || '/audit-payload-' || repeat('00', 32) || '.txt', decode(repeat('00', 32), 'hex'), 'payload-version',
			 'org/' || org_id::text || '/documents/' || id::text || '/audit-signature-' || repeat('00', 32) || '.txt', decode(repeat('00', 32), 'hex'), 'signature-version'
			FROM documents WHERE id = $1`, finalID, completionAt, retainUntil)
		return insertErr
	}
	if err := insertFinalizationIntent(wantFinalDeadline.Add(time.Second)); err == nil {
		t.Fatal("finalization intent accepted a deadline different from its document commitment")
	}
	must(t, insertFinalizationIntent(wantFinalDeadline), "insert exact-deadline finalization intent")
	if _, err := pool.Exec(ctx,
		`UPDATE document_finalization_intents SET retain_until = retain_until + interval '1 second' WHERE document_id = $1`,
		finalID); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("finalization intent deadline rewrite = %v, want immutable-trigger refusal", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE documents SET finalization_retain_until = finalization_retain_until + interval '1 second' WHERE id = $1`,
		finalID); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("document deadline rewrite = %v, want immutable-trigger refusal", err)
	}

	// A down migration must first refuse every durable/in-flight commitment and
	// leave its schema intact. Once this scratch inventory is explicitly drained,
	// a clean rollback is supported and removes all three columns atomically.
	goose.SetBaseFS(nil)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	err = goose.DownTo(migConn, "../db/migrations", 59)
	if err == nil || !strings.Contains(err.Error(), "durable retention commitments") {
		t.Fatalf("migration 00060 down with durable claims = %v, want safe refusal", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 60)
	assertRetentionDeadlineColumns(t, ctx, pool, true)

	_, err = pool.Exec(ctx, `DELETE FROM document_finalization_intents`)
	must(t, err, "drain finalization intents before rollback")
	_, err = pool.Exec(ctx, `DELETE FROM send_sealing_intents`)
	must(t, err, "drain send intents before rollback")
	_, err = pool.Exec(ctx,
		`DELETE FROM documents WHERE id <> $1 AND id <> $2`, historicalID, finalID)
	must(t, err, "drain lifecycle documents before rollback")
	_, err = pool.Exec(ctx,
		`UPDATE documents
		 SET status = 'completed', completed_at = completion_effective_at
		 WHERE id = $1`, finalID)
	must(t, err, "publish completed document while preserving durable retention commitment")
	err = goose.DownTo(migConn, "../db/migrations", 59)
	if err == nil || !strings.Contains(err.Error(), "durable retention commitments") {
		t.Fatalf("migration 00060 down after completed retained evidence = %v, want permanent-commitment refusal", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 60)
	assertRetentionDeadlineColumns(t, ctx, pool, true)
	_, err = pool.Exec(ctx, `DELETE FROM documents WHERE id = $1`, finalID)
	must(t, err, "remove completed scratch commitment before clean rollback")
	must(t, goose.DownTo(migConn, "../db/migrations", 59), "roll back retention deadline migration after drain")
	assertAppliedMigrationVersion(t, ctx, pool, 59)
	assertRetentionDeadlineColumns(t, ctx, pool, false)
	var helperRemoved bool
	must(t, pool.QueryRow(ctx,
		`SELECT to_regprocedure('hash_evidence_retain_until(timestamptz,integer)') IS NULL`,
	).Scan(&helperRemoved), "inspect retention helper after rollback")
	if !helperRemoved {
		t.Fatal("clean migration 00060 rollback left hash_evidence_retain_until behind")
	}
}

func assertRetentionDeadlineColumns(t *testing.T, ctx context.Context, pool *pgxpool.Pool, want bool) {
	t.Helper()
	var count int
	err := pool.QueryRow(ctx,
		`SELECT count(*)
		 FROM information_schema.columns
		 WHERE table_schema = 'public'
		   AND (table_name, column_name) IN (
		     ('send_sealing_intents', 'retain_until'),
		     ('documents', 'finalization_retain_until'),
		     ('document_finalization_intents', 'retain_until')
		   )`,
	).Scan(&count)
	must(t, err, "inspect retention deadline columns")
	wantCount := 0
	if want {
		wantCount = 3
	}
	if count != wantCount {
		t.Fatalf("retention deadline column count = %d, want %d", count, wantCount)
	}
}
