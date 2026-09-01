// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	"github.com/bright-interaction/hash/internal/audit"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
)

// Migration 00059 refuses to guess the timestamp already signed by an older
// in-flight renderer. Once the inventory is drained, it backfills historical
// terminal rows, enforces the timestamp/state relationship, and makes a
// finalizing claim's effective instant immutable across retry and rollback.
func TestCompletionTimestampMigrationCutoverAndRollbackGuardsE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	migConn := stdlibConn(t, pool)
	defer migConn.Close()

	must(t, mdb.RunMigrationsUpTo(migConn, 58), "migrate scratch database to pre-completion-timestamp version 58")
	historicalID := seedDocument(t, ctx, pool, "completion timestamp historical")
	inFlightID := seedDocument(t, ctx, pool, "completion timestamp in flight")
	historicalCompletedAt := time.Date(2026, 8, 30, 9, 8, 7, 654321000, time.UTC)
	_, err := pool.Exec(ctx,
		`UPDATE documents SET status = 'completed', completed_at = $2 WHERE id = $1`,
		historicalID, historicalCompletedAt)
	must(t, err, "seed historical completed document")
	_, err = pool.Exec(ctx, `UPDATE documents SET status = 'finalizing' WHERE id = $1`, inFlightID)
	must(t, err, "seed older in-flight finalization")

	err = mdb.RunMigrationsUpTo(migConn, 59)
	if err == nil || !strings.Contains(err.Error(), "in-flight finalization") {
		t.Fatalf("migration 00059 with active finalization = %v, want explicit inventory refusal", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 58)
	var completionColumnAbsent bool
	must(t, pool.QueryRow(ctx,
		`SELECT NOT EXISTS (
		   SELECT 1 FROM information_schema.columns
		   WHERE table_schema = 'public' AND table_name = 'documents'
		     AND column_name = 'completion_effective_at'
		)`).Scan(&completionColumnAbsent), "inspect failed migration schema")
	if !completionColumnAbsent {
		t.Fatal("failed migration 00059 left completion_effective_at behind")
	}

	_, err = pool.Exec(ctx, `UPDATE documents SET status = 'in_progress' WHERE id = $1`, inFlightID)
	must(t, err, "drain older in-flight finalization inventory")
	var inFlightOrgID uuid.UUID
	must(t, pool.QueryRow(ctx, `SELECT org_id FROM documents WHERE id = $1`, inFlightID).Scan(&inFlightOrgID), "load finalizing document organization")
	preCutoverDigest := sha256.Sum256([]byte("pre-cutover finalization intent"))
	preCutoverBase := path.Join("org", inFlightOrgID.String(), "documents", inFlightID.String())
	_, err = pool.Exec(ctx, `INSERT INTO document_finalization_intents (
		document_id, org_id, mode,
		final_pdf_key, final_pdf_sha256, final_pdf_version_id,
		audit_cert_key, audit_cert_sha256, audit_cert_version_id,
		audit_payload_key, audit_payload_sha256, audit_payload_version_id,
		audit_signature_key, audit_signature_sha256, audit_signature_version_id
	) VALUES ($1,$2,'signature',$3,$4,'final-v',$5,$4,'cert-v',$6,$4,'payload-v',$7,$4,'signature-v')`,
		inFlightID, inFlightOrgID,
		path.Join(preCutoverBase, "final-"+hex.EncodeToString(preCutoverDigest[:])+".pdf"), preCutoverDigest[:],
		path.Join(preCutoverBase, "audit-"+hex.EncodeToString(preCutoverDigest[:])+".pdf"),
		path.Join(preCutoverBase, "audit-payload-"+hex.EncodeToString(preCutoverDigest[:])+".txt"),
		path.Join(preCutoverBase, "audit-signature-"+hex.EncodeToString(preCutoverDigest[:])+".txt"))
	must(t, err, "seed orphaned pre-cutover finalization intent")
	err = mdb.RunMigrationsUpTo(migConn, 59)
	if err == nil || !strings.Contains(err.Error(), "in-flight finalization") {
		t.Fatalf("migration 00059 with active intent = %v, want explicit inventory refusal", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 58)
	_, err = pool.Exec(ctx, `DELETE FROM document_finalization_intents WHERE document_id=$1`, inFlightID)
	must(t, err, "drain older finalization intent inventory")
	must(t, mdb.RunMigrationsUpTo(migConn, 59), "retry completion timestamp migration after drain")
	assertAppliedMigrationVersion(t, ctx, pool, 59)

	var historicalBound bool
	var backfilled, completedAt time.Time
	must(t, pool.QueryRow(ctx,
		`SELECT completion_effective_at_bound, completion_effective_at, completed_at FROM documents WHERE id = $1`, historicalID,
	).Scan(&historicalBound, &backfilled, &completedAt), "read historical completion timestamp backfill")
	if historicalBound || !backfilled.Equal(historicalCompletedAt) || !completedAt.Equal(historicalCompletedAt) {
		t.Fatalf("historical timestamp backfill = bound:%v %s/%s, want legacy-unbound %s", historicalBound, backfilled, completedAt, historicalCompletedAt)
	}
	if _, err := pool.Exec(ctx, `UPDATE documents SET completion_effective_at_bound=TRUE WHERE id=$1`, historicalID); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("legacy completion provenance rewrite = %v, want immutable-trigger refusal", err)
	}
	// Legacy-unbound is an inventory classification, not an application-facing
	// escape hatch. A row inserted after the cutover cannot opt out of the new
	// signed timestamp commitment even when it supplies FALSE explicitly.
	if _, err := pool.Exec(ctx, `INSERT INTO documents (
		org_id, name, status, routing_mode, source_kind, blocks_json, variables_json,
		sender_id, completion_effective_at_bound
	) SELECT org_id, 'forged legacy completion', 'draft', routing_mode, source_kind,
	         blocks_json, variables_json, sender_id, FALSE
	    FROM documents WHERE id=$1`, inFlightID); err == nil || !strings.Contains(err.Error(), "must bind") {
		t.Fatalf("post-cutover legacy provenance insert = %v, want trigger refusal", err)
	}

	// A lifecycle state cannot claim finalizing without the timestamp being set
	// in the same statement. This is the migration-59 form of the source query;
	// keeping it raw prevents later generated schema additions from making this
	// cutover test accidentally depend on migration 60+.
	if _, err := pool.Exec(ctx, `UPDATE documents SET status = 'finalizing' WHERE id = $1`, inFlightID); err == nil {
		t.Fatal("completion timestamp state constraint accepted finalizing without an effective timestamp")
	}
	var original, claimUpdatedAt time.Time
	var originalBound bool
	claimTx, err := pool.Begin(ctx)
	must(t, err, "begin contended finalization claim")
	defer func() { _ = claimTx.Rollback(ctx) }()
	var transactionStarted time.Time
	must(t, claimTx.QueryRow(ctx, `SELECT now()`).Scan(&transactionStarted), "capture finalization transaction start")
	time.Sleep(5 * time.Millisecond)
	must(t, claimTx.QueryRow(ctx, `UPDATE documents
		SET status = 'finalizing', completion_effective_at_bound = TRUE,
		    completion_effective_at = COALESCE(completion_effective_at, statement_timestamp()),
		    updated_at = statement_timestamp()
		WHERE id = $1 AND org_id = $2 AND status = 'in_progress' AND deleted_at IS NULL
		RETURNING completion_effective_at, completion_effective_at_bound, updated_at`, inFlightID, inFlightOrgID,
	).Scan(&original, &originalBound, &claimUpdatedAt), "claim finalization with durable timestamp")
	must(t, claimTx.Commit(ctx), "commit finalization claim")
	if original.IsZero() || !originalBound {
		t.Fatalf("finalization claim has invalid completion timestamp/binding: %s/%v", original, originalBound)
	}
	if !original.After(transactionStarted) {
		t.Fatalf("completion-effective timestamp %s did not follow pre-readiness transaction start %s", original, transactionStarted)
	}
	if !claimUpdatedAt.Equal(original) {
		t.Fatalf("finalizing updated_at = %s, want exact claim time %s", claimUpdatedAt, original)
	}
	// Keep this schema-59 fixture valid whether seedDocument ran before the
	// version-pin cutover (FALSE) or was inserted afterward with the TRUE
	// default. It has no source-object keys, so the one-way transition is safe.
	tag, err := pool.Exec(ctx, `UPDATE documents
		SET evidence_version_pins_required=TRUE
		WHERE id=$1 AND org_id=$2 AND status='finalizing'
		  AND evidence_version_pins_required=FALSE`, inFlightID, inFlightOrgID)
	must(t, err, "pin legacy finalizing document evidence versions")
	if tag.RowsAffected() > 1 {
		t.Fatalf("legacy document pin rows = %d, want at most 1", tag.RowsAffected())
	}
	var documentPinsRequired bool
	must(t, pool.QueryRow(ctx, `SELECT evidence_version_pins_required FROM documents WHERE id=$1`, inFlightID).Scan(&documentPinsRequired), "read finalizing document pin state")
	if !documentPinsRequired {
		t.Fatal("finalizing document evidence versions remain unpinned")
	}

	// Simulate a process exit after the durable claim. A new pool must observe
	// the same instant, persist it in the staged intent, and survive another
	// process exit before the terminal publication.
	resumePool, err := pgxpool.NewWithConfig(ctx, pool.Config().Copy())
	must(t, err, "open first crash-resume pool")
	var reloaded time.Time
	var reloadedBound bool
	must(t, resumePool.QueryRow(ctx,
		`SELECT completion_effective_at, completion_effective_at_bound
		 FROM documents WHERE id = $1 AND org_id = $2`, inFlightID, inFlightOrgID,
	).Scan(&reloaded, &reloadedBound), "reload durable finalization claim after process exit")
	if !reloaded.Equal(original) || !reloadedBound {
		resumePool.Close()
		t.Fatalf("completion timestamp after claim restart = %s/%v, want %s/true", reloaded, reloadedBound, original)
	}
	type artifact struct {
		prefix, suffix, version string
		body                    []byte
	}
	artifacts := []artifact{
		{prefix: "final-", suffix: ".pdf", version: "final-version", body: []byte("final body")},
		{prefix: "audit-", suffix: ".pdf", version: "certificate-version", body: []byte("certificate")},
		{prefix: "audit-payload-", suffix: ".txt", version: "payload-version", body: []byte("signed payload")},
		{prefix: "audit-signature-", suffix: ".txt", version: "signature-version", body: []byte("detached signature")},
	}
	keys := make([]string, len(artifacts))
	digests := make([][]byte, len(artifacts))
	artifactDir := path.Join("org", inFlightOrgID.String(), "documents", inFlightID.String())
	for i, artifact := range artifacts {
		digest := sha256.Sum256(artifact.body)
		digests[i] = append([]byte(nil), digest[:]...)
		keys[i] = path.Join(artifactDir, artifact.prefix+hex.EncodeToString(digest[:])+artifact.suffix)
	}
	var intentEffective time.Time
	must(t, resumePool.QueryRow(ctx, `INSERT INTO document_finalization_intents (
		document_id, org_id, mode, completion_effective_at,
		final_pdf_key, final_pdf_sha256, final_pdf_version_id,
		audit_cert_key, audit_cert_sha256, audit_cert_version_id,
		audit_payload_key, audit_payload_sha256, audit_payload_version_id,
		audit_signature_key, audit_signature_sha256, audit_signature_version_id
	) VALUES ($1,$2,'signature',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
	RETURNING completion_effective_at`,
		inFlightID, inFlightOrgID, reloaded,
		keys[0], digests[0], artifacts[0].version,
		keys[1], digests[1], artifacts[1].version,
		keys[2], digests[2], artifacts[2].version,
		keys[3], digests[3], artifacts[3].version,
	).Scan(&intentEffective), "persist crash-resumable finalization intent")
	if !intentEffective.Equal(original) {
		resumePool.Close()
		t.Fatalf("intent completion timestamp = %s, want %s", intentEffective, original)
	}
	tag, err = resumePool.Exec(ctx, `UPDATE document_finalization_intents
		SET retention_started_at = COALESCE(retention_started_at, now()), updated_at = now()
		WHERE document_id = $1 AND org_id = $2 AND retention_completed_at IS NULL`, inFlightID, inFlightOrgID)
	must(t, err, "mark finalization retention started")
	if tag.RowsAffected() != 1 {
		resumePool.Close()
		t.Fatalf("retention-start rows = %d, want 1", tag.RowsAffected())
	}
	tag, err = resumePool.Exec(ctx, `UPDATE document_finalization_intents
		SET retention_completed_at = COALESCE(retention_completed_at, now()),
		    attempts = attempts + 1, last_error = NULL, updated_at = now()
		WHERE document_id = $1 AND org_id = $2 AND retention_started_at IS NOT NULL`, inFlightID, inFlightOrgID)
	must(t, err, "mark finalization retention complete")
	if tag.RowsAffected() != 1 {
		resumePool.Close()
		t.Fatalf("retention-complete rows = %d, want 1", tag.RowsAffected())
	}
	resumePool.Close()

	time.Sleep(5 * time.Millisecond)
	publishPool, err := pgxpool.NewWithConfig(ctx, pool.Config().Copy())
	must(t, err, "open second crash-resume pool")
	var completedStatus string
	var completedEffective, completedAtAfterRestart time.Time
	must(t, publishPool.QueryRow(ctx, `UPDATE documents
		SET final_pdf_key=$1, final_pdf_sha=$2, final_pdf_version_id=$3,
		    audit_cert_key=$4, audit_cert_sha256=$5, audit_cert_version_id=$6,
		    audit_payload_key=$7, audit_payload_sha256=$8, audit_payload_version_id=$9,
		    audit_signature_key=$10, audit_signature_sha256=$11, audit_signature_version_id=$12,
		    completed_at=documents.completion_effective_at, status='completed', updated_at=now()
		WHERE documents.id=$13 AND documents.org_id=$14
		  AND documents.status='finalizing' AND documents.completion_effective_at_bound
		  AND documents.evidence_version_pins_required
		  AND EXISTS (SELECT 1 FROM document_finalization_intents i
		      WHERE i.document_id=documents.id AND i.org_id=documents.org_id
		        AND i.completion_effective_at=documents.completion_effective_at
		        AND i.retention_completed_at IS NOT NULL
		        AND i.final_pdf_key=$1 AND i.final_pdf_sha256=$2 AND i.final_pdf_version_id=$3
		        AND i.audit_cert_key=$4 AND i.audit_cert_sha256=$5 AND i.audit_cert_version_id=$6
		        AND i.audit_payload_key=$7 AND i.audit_payload_sha256=$8 AND i.audit_payload_version_id=$9
		        AND i.audit_signature_key=$10 AND i.audit_signature_sha256=$11 AND i.audit_signature_version_id=$12
		        AND i.evidence_version_pins_required)
		RETURNING status, completion_effective_at, completed_at`,
		keys[0], digests[0], artifacts[0].version,
		keys[1], digests[1], artifacts[1].version,
		keys[2], digests[2], artifacts[2].version,
		keys[3], digests[3], artifacts[3].version,
		inFlightID, inFlightOrgID,
	).Scan(&completedStatus, &completedEffective, &completedAtAfterRestart), "publish finalization after second process exit")
	publishPool.Close()
	if completedStatus != "completed" || !completedEffective.Equal(original) || !completedAtAfterRestart.Equal(original) {
		t.Fatalf("terminal completion = %s effective %s completed %s, want completed/%s", completedStatus, completedEffective, completedAtAfterRestart, original)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE documents SET completion_effective_at = completion_effective_at + interval '1 microsecond' WHERE id = $1`,
		inFlightID); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("completion timestamp rewrite = %v, want immutable-trigger refusal", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE documents SET completed_at = completed_at + interval '1 microsecond' WHERE id = $1`,
		inFlightID); err == nil || !strings.Contains(err.Error(), "documents_completion_timestamps_consistent") {
		t.Fatalf("terminal completed_at drift = %v, want timestamp-constraint refusal", err)
	}
	var persisted, persistedCompleted time.Time
	must(t, pool.QueryRow(ctx,
		`SELECT completion_effective_at, completed_at FROM documents WHERE id = $1`, inFlightID,
	).Scan(&persisted, &persistedCompleted), "reload completion timestamp after rejected rewrite")
	if !persisted.Equal(original) || !persistedCompleted.Equal(original) {
		t.Fatalf("rejected rewrite changed completion timestamps from %s to effective=%s completed=%s", original, persisted, persistedCompleted)
	}
	if _, err := pool.Exec(ctx, `UPDATE documents SET completion_effective_at_bound=FALSE WHERE id=$1`, inFlightID); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("bound completion provenance rewrite = %v, want immutable-trigger refusal", err)
	}
	tag, err = pool.Exec(ctx, `DELETE FROM document_finalization_intents WHERE document_id=$1 AND org_id=$2`, inFlightID, inFlightOrgID)
	must(t, err, "remove published finalization intent")
	if tag.RowsAffected() != 1 {
		t.Fatalf("published finalization intent delete rows = %d, want 1", tag.RowsAffected())
	}

	// Even after normal publication deletes the durable intent, rolling back
	// would lose the provenance required to distinguish this bound completion
	// from historical evidence. The real Goose down path must be one-way now.
	goose.SetBaseFS(nil)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	err = goose.DownTo(migConn, "../db/migrations", 58)
	if err == nil || !strings.Contains(err.Error(), "bound evidence has been completed") {
		t.Fatalf("migration 00059 down after a bound completion = %v, want one-way refusal", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 59)
	var completionColumnPresent bool
	must(t, pool.QueryRow(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM information_schema.columns
		   WHERE table_schema = 'public' AND table_name = 'documents'
		     AND column_name = 'completion_effective_at'
		)`).Scan(&completionColumnPresent), "inspect refused rollback schema")
	if !completionColumnPresent {
		t.Fatal("refused migration 00059 rollback dropped completion_effective_at")
	}
}

func TestCompletionTimestampMigrationCleanDownReapplyPreservesClassificationE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	migConn := stdlibConn(t, pool)
	defer migConn.Close()

	must(t, mdb.RunMigrationsUpTo(migConn, 58), "migrate clean rollback database to version 58")
	historicalID := seedDocument(t, ctx, pool, "completion timestamp clean rollback historical")
	activeID := seedDocument(t, ctx, pool, "completion timestamp clean rollback active")
	historicalCompletedAt := time.Date(2026, 8, 29, 6, 5, 4, 321000000, time.UTC)
	legacyEnvelopeID, legacyChildID, legacyEnvelopeAt, legacyChildAt := seedLegacyCompletedEnvelopeWithDistinctTimestamps(t, ctx, pool)
	_, err := pool.Exec(ctx,
		`UPDATE documents SET status = 'completed', completed_at = $2 WHERE id = $1`,
		historicalID, historicalCompletedAt)
	must(t, err, "seed clean-rollback historical completion")
	must(t, mdb.RunMigrationsUpTo(migConn, 59), "apply completion timestamp migration before clean rollback")
	assertCompletionClassifications(t, ctx, pool, historicalID, activeID, historicalCompletedAt)
	assertLegacyEnvelopeCompletionClassification(t, ctx, pool, legacyEnvelopeID, legacyChildID, legacyEnvelopeAt, legacyChildAt)

	goose.SetBaseFS(nil)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	must(t, goose.DownTo(migConn, "../db/migrations", 58), "clean rollback completion timestamp migration")
	assertAppliedMigrationVersion(t, ctx, pool, 58)
	var completionColumnAbsent bool
	must(t, pool.QueryRow(ctx,
		`SELECT NOT EXISTS (
		   SELECT 1 FROM information_schema.columns
		   WHERE table_schema = 'public' AND table_name = 'documents'
		     AND column_name IN ('completion_effective_at', 'completion_effective_at_bound')
		)`).Scan(&completionColumnAbsent), "inspect clean rollback schema")
	if !completionColumnAbsent {
		t.Fatal("clean migration 00059 rollback left completion provenance columns behind")
	}

	must(t, mdb.RunMigrationsUpTo(migConn, 59), "reapply completion timestamp migration after clean rollback")
	assertAppliedMigrationVersion(t, ctx, pool, 59)
	assertCompletionClassifications(t, ctx, pool, historicalID, activeID, historicalCompletedAt)
	assertLegacyEnvelopeCompletionClassification(t, ctx, pool, legacyEnvelopeID, legacyChildID, legacyEnvelopeAt, legacyChildAt)
}

// Migration 00061 can preserve an Article 13 epoch that is ahead of the
// current database clock, and legacy active envelope children can have later
// sent_at values than their root. The finalization claim must still choose one
// instant strictly after the whole family's send/response evidence and derive
// retention from that same instant.
func TestCompletionTimestampFollowsArticle13EnvelopeAndSignatureHighWatersE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	migConn := stdlibConn(t, pool)
	defer migConn.Close()
	must(t, mdb.RunMigrationsUpTo(migConn, 60), "migrate completion chronology database to pre-epoch version 60")

	parentID := seedDocument(t, ctx, pool, "completion chronology envelope")
	_, err := pool.Exec(ctx, `UPDATE documents SET is_envelope=TRUE WHERE id=$1`, parentID)
	must(t, err, "mark completion chronology envelope")
	childOneID := seedEnvelopeChild(t, ctx, pool, parentID, 1)
	childTwoID := seedEnvelopeChild(t, ctx, pool, parentID, 2)
	orgID := documentOrgID(t, ctx, pool, parentID)

	var recipientID, fieldID uuid.UUID
	tokenHash := sha256.Sum256([]byte("completion chronology recipient token"))
	must(t, pool.QueryRow(ctx, `INSERT INTO recipients (
		document_id, role, email, name, magic_token_hash
	) VALUES ($1, 'signer', 'chronology@example.test', 'Chronology Signer', $2)
	RETURNING id`, parentID, tokenHash[:]).Scan(&recipientID), "seed completion chronology recipient")
	must(t, pool.QueryRow(ctx, `INSERT INTO document_fields (
		document_id, recipient_id, type, page, x_pct, y_pct, w_pct, h_pct
	) VALUES ($1, $2, 'signature', 1, 10, 10, 20, 5)
	RETURNING id`, parentID, recipientID).Scan(&fieldID), "seed completion chronology signature field")

	parentSentAt := time.Date(2099, time.January, 2, 3, 4, 5, 123456000, time.UTC)
	childOneSentAt := parentSentAt.Add(time.Hour)
	childTwoSentAt := parentSentAt.Add(2 * time.Hour)
	for _, item := range []struct {
		id     uuid.UUID
		sentAt time.Time
	}{
		{parentID, parentSentAt},
		{childOneID, childOneSentAt},
		{childTwoID, childTwoSentAt},
	} {
		_, err = pool.Exec(ctx, `UPDATE documents SET status='in_progress', sent_at=$2 WHERE id=$1`, item.id, item.sentAt)
		must(t, err, "seed active completion chronology document")
		appendArticle13SendEvent(t, ctx, pool, item.id, article13MarkerPayload(t, item.sentAt))
	}
	must(t, mdb.RunMigrationsUpTo(migConn, 61), "apply Article 13 epoch migration to future envelope chronology")
	assertAppliedMigrationVersion(t, ctx, pool, 61)

	signatureAt := childTwoSentAt.Add(3 * time.Hour)
	imageDigest := sha256.Sum256([]byte("completion chronology signature image"))
	_, err = pool.Exec(ctx, `UPDATE recipients SET status='signed', signed_at=$2 WHERE id=$1`, recipientID, signatureAt)
	must(t, err, "seed future recipient response high-water")
	_, err = pool.Exec(ctx, `INSERT INTO signatures (
		document_id, recipient_id, field_id, font, typed_name,
		image_storage_key, image_sha256, image_version_id, signed_at
	) VALUES ($1,$2,$3,'Dancing Script','Chronology Signer',$4,$5,'signature-version',$6)`,
		parentID, recipientID, fieldID,
		path.Join("org", orgID.String(), "documents", parentID.String(), "signatures", "chronology.png"),
		imageDigest[:], signatureAt)
	must(t, err, "seed future signature high-water")

	claimed, err := generated.New(pool).BeginDocumentFinalization(ctx, generated.BeginDocumentFinalizationParams{
		RetentionYears: 7,
		ID:             parentID,
		OrgID:          orgID,
	})
	must(t, err, "claim finalization after future Article 13/signature high-waters")
	wantEffectiveAt := signatureAt.Add(time.Microsecond)
	if claimed == nil || claimed.Status != "finalizing" || !claimed.CompletionEffectiveAtBound ||
		!claimed.CompletionEffectiveAt.Valid || !claimed.CompletionEffectiveAt.Time.Equal(wantEffectiveAt) {
		t.Fatalf("completion claim = %+v, want bound finalizing at %s", claimed, wantEffectiveAt)
	}
	if !claimed.CompletionEffectiveAt.Time.After(parentSentAt) ||
		!claimed.CompletionEffectiveAt.Time.After(childOneSentAt) ||
		!claimed.CompletionEffectiveAt.Time.After(childTwoSentAt) ||
		!claimed.CompletionEffectiveAt.Time.After(signatureAt) {
		t.Fatalf("completion claim %s does not strictly follow every family high-water", claimed.CompletionEffectiveAt.Time)
	}
	if !claimed.UpdatedAt.Time.Equal(wantEffectiveAt) {
		t.Fatalf("finalization updated_at = %s, want exact effective instant %s", claimed.UpdatedAt.Time, wantEffectiveAt)
	}
	var expectedRetainUntil time.Time
	must(t, pool.QueryRow(ctx, `SELECT hash_evidence_retain_until($1, 7)`, wantEffectiveAt).Scan(&expectedRetainUntil), "derive completion chronology retention deadline")
	if !claimed.FinalizationRetainUntil.Valid || !claimed.FinalizationRetainUntil.Time.Equal(expectedRetainUntil) {
		t.Fatalf("finalization retain_until = %+v, want %s from exact effective instant", claimed.FinalizationRetainUntil, expectedRetainUntil)
	}
}

// A child-addressed mutation owns the child row lock until its comment and
// audit event commit. The family claim must wait for that lock before it
// allocates the completion high-water, then atomically freeze every child to
// the root's exact completion and retention commitments. A fresh child comment
// must observe finalizing and fail without adding a post-high-water row.
func TestEnvelopeFamilyFreezeDrainsChildMutationBeforeHighWaterE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	migConn := stdlibConn(t, pool)
	defer migConn.Close()
	must(t, mdb.RunMigrationsUpTo(migConn, 60), "migrate family-freeze database to pre-epoch version 60")

	parentID := seedDocument(t, ctx, pool, "family freeze envelope")
	_, err := pool.Exec(ctx, `UPDATE documents SET is_envelope=TRUE WHERE id=$1`, parentID)
	must(t, err, "mark family-freeze envelope")
	childOneID := seedEnvelopeChild(t, ctx, pool, parentID, 1)
	childTwoID := seedEnvelopeChild(t, ctx, pool, parentID, 2)
	_, err = pool.Exec(ctx, `UPDATE documents SET requires_signature=FALSE WHERE id=$1`, childTwoID)
	must(t, err, "make one family-freeze child acknowledgement-only")
	orgID := documentOrgID(t, ctx, pool, parentID)
	var senderID uuid.UUID
	must(t, pool.QueryRow(ctx, `SELECT sender_id FROM documents WHERE id=$1`, parentID).Scan(&senderID), "load family-freeze sender")

	sentAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	for i, id := range []uuid.UUID{parentID, childOneID, childTwoID} {
		memberSentAt := sentAt.Add(time.Duration(i) * time.Microsecond)
		_, err = pool.Exec(ctx, `UPDATE documents SET status='in_progress', sent_at=$2 WHERE id=$1`, id, memberSentAt)
		must(t, err, "seed active family-freeze member")
		appendArticle13SendEvent(t, ctx, pool, id, article13MarkerPayload(t, memberSentAt))
	}
	must(t, mdb.RunMigrationsUpTo(migConn, 62), "apply Article 13 and inbox migrations to family-freeze database")

	q := generated.New(pool)
	candidates, err := q.GetStrandedDocuments(ctx, 50)
	must(t, err, "select active stranded roots")
	if len(candidates) != 0 {
		t.Fatalf("active envelope child was selected for standalone retry: %+v", candidates)
	}

	mutationTx, err := pool.Begin(ctx)
	must(t, err, "begin child mutation")
	defer func() { _ = mutationTx.Rollback(ctx) }()
	mutationQ := generated.New(mutationTx)
	lockedChild, err := mutationQ.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: childOneID, OrgID: orgID})
	must(t, err, "lock child for mutation")
	if lockedChild.Status != "in_progress" {
		t.Fatalf("child mutation locked status %q, want in_progress", lockedChild.Status)
	}
	_, err = mutationQ.CreateComment(ctx, generated.CreateCommentParams{
		DocumentID: childOneID,
		UserID:     pgtype.UUID{Bytes: senderID, Valid: true},
		AuthorName: "Concurrent Sender",
		AuthorSide: "sender",
		Body:       "commits before the family high-water",
	})
	must(t, err, "insert child comment in mutation")
	logger := audit.New(generated.New(pool), pool)
	_, err = logger.LogTx(ctx, mutationTx, audit.Entry{
		OrgID: orgID, DocumentID: &childOneID, Kind: audit.KindCommentPosted,
		Payload: map[string]any{"side": "sender"},
	})
	must(t, err, "append child comment event in mutation")

	rootLocked := make(chan struct{})
	freezeResult := make(chan error, 1)
	go func() {
		freezeTx, beginErr := pool.Begin(ctx)
		if beginErr != nil {
			freezeResult <- beginErr
			return
		}
		defer func() { _ = freezeTx.Rollback(ctx) }()
		q := generated.New(freezeTx)
		root, lockErr := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: parentID, OrgID: orgID})
		if lockErr != nil {
			freezeResult <- lockErr
			return
		}
		close(rootLocked)
		listed, listErr := q.ListEnvelopeChildren(ctx, generated.ListEnvelopeChildrenParams{
			ParentEnvelopeID: pgtype.UUID{Bytes: parentID, Valid: true}, OrgID: orgID,
		})
		if listErr != nil {
			freezeResult <- listErr
			return
		}
		sort.Slice(listed, func(i, j int) bool { return listed[i].ID.String() < listed[j].ID.String() })
		for _, child := range listed {
			if _, lockErr = q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: child.ID, OrgID: orgID}); lockErr != nil {
				freezeResult <- lockErr
				return
			}
		}
		claimed, claimErr := q.BeginDocumentFinalization(ctx, generated.BeginDocumentFinalizationParams{
			RetentionYears: 7, ID: root.ID, OrgID: root.OrgID,
		})
		if claimErr != nil {
			freezeResult <- claimErr
			return
		}
		frozen, freezeErr := q.BeginEnvelopeChildrenFinalization(ctx, generated.BeginEnvelopeChildrenFinalizationParams{
			ParentEnvelopeID: pgtype.UUID{Bytes: parentID, Valid: true}, OrgID: orgID,
		})
		if freezeErr != nil {
			freezeResult <- freezeErr
			return
		}
		if len(frozen) != len(listed) {
			freezeResult <- errors.New("family freeze returned a partial child set")
			return
		}
		for _, child := range frozen {
			if child.Status != "finalizing" || !child.CompletionEffectiveAtBound ||
				!child.CompletionEffectiveAt.Time.Equal(claimed.CompletionEffectiveAt.Time) ||
				!child.FinalizationRetainUntil.Time.Equal(claimed.FinalizationRetainUntil.Time) {
				freezeResult <- errors.New("family freeze returned divergent child commitments")
				return
			}
		}
		freezeResult <- freezeTx.Commit(ctx)
	}()

	<-rootLocked
	select {
	case freezeErr := <-freezeResult:
		t.Fatalf("family freeze bypassed held child mutation lock: %v", freezeErr)
	case <-time.After(100 * time.Millisecond):
	}
	must(t, mutationTx.Commit(ctx), "commit child mutation before family high-water")
	select {
	case freezeErr := <-freezeResult:
		must(t, freezeErr, "commit family freeze after child mutation")
	case <-time.After(2 * time.Second):
		t.Fatal("family freeze did not resume after child mutation committed")
	}

	var effectiveAt, commentEventAt time.Time
	must(t, pool.QueryRow(ctx, `SELECT completion_effective_at FROM documents WHERE id=$1`, parentID).Scan(&effectiveAt), "read family completion high-water")
	must(t, pool.QueryRow(ctx, `SELECT created_at FROM events
		WHERE document_id=$1 AND kind='document.comment_posted'
		ORDER BY created_at DESC, id DESC LIMIT 1`, childOneID).Scan(&commentEventAt), "read drained child comment event")
	if !effectiveAt.After(commentEventAt) {
		t.Fatalf("family completion high-water %s does not follow child event %s", effectiveAt, commentEventAt)
	}

	candidates, err = q.GetStrandedDocuments(ctx, 50)
	must(t, err, "select frozen stranded roots")
	if len(candidates) != 1 || candidates[0].ID != parentID || candidates[0].ParentEnvelopeID.Valid {
		t.Fatalf("frozen retry candidates = %+v, want only root %s", candidates, parentID)
	}
	engine := &sign.Engine{Pool: pool, Queries: q, Audit: logger}
	if err := engine.FinalizeStranded(ctx, orgID, childOneID); !errors.Is(err, sign.ErrEnvelopeChildFinalization) {
		t.Fatalf("standalone child retry error = %v, want ErrEnvelopeChildFinalization", err)
	}
	var childIntents int
	must(t, pool.QueryRow(ctx, `SELECT count(*) FROM document_finalization_intents WHERE document_id IN ($1,$2)`, childOneID, childTwoID).Scan(&childIntents), "count child finalization intents")
	if childIntents != 0 {
		t.Fatalf("standalone child refusal created %d finalization intents", childIntents)
	}

	if _, err := engine.SenderComment(ctx, orgID, childOneID, senderID, "Late Sender", "must not cross the high-water"); !errors.Is(err, sign.ErrDocumentNotCommentable) {
		t.Fatalf("post-freeze child comment error = %v, want ErrDocumentNotCommentable", err)
	}
	var comments, commentEvents int
	must(t, pool.QueryRow(ctx, `SELECT count(*) FROM document_comments WHERE document_id=$1`, childOneID).Scan(&comments), "count child comments after freeze")
	must(t, pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.comment_posted'`, childOneID).Scan(&commentEvents), "count child comment events after freeze")
	if comments != 1 || commentEvents != 1 {
		t.Fatalf("post-freeze child mutation changed rows: comments=%d events=%d, want 1/1", comments, commentEvents)
	}
}

func seedLegacyCompletedEnvelopeWithDistinctTimestamps(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID, time.Time, time.Time) {
	t.Helper()
	parentID := seedDocument(t, ctx, pool, "completion timestamp legacy envelope")
	_, err := pool.Exec(ctx, `UPDATE documents SET is_envelope=TRUE WHERE id=$1`, parentID)
	must(t, err, "mark legacy envelope parent")
	var childID uuid.UUID
	must(t, pool.QueryRow(ctx, `INSERT INTO documents (
		org_id, name, status, routing_mode, source_kind, blocks_json, variables_json,
		sender_id, parent_envelope_id, envelope_position
	) SELECT org_id, 'legacy envelope child', 'draft', routing_mode, source_kind,
	         blocks_json, variables_json, sender_id, id, 1
	    FROM documents WHERE id=$1
	RETURNING id`, parentID).Scan(&childID), "seed legacy envelope child")
	parentAt := time.Date(2026, 8, 28, 7, 6, 5, 111111000, time.UTC)
	childAt := parentAt.Add(37 * time.Microsecond)
	_, err = pool.Exec(ctx, `UPDATE documents
		SET status='completed', completed_at=CASE WHEN id=$1 THEN $3::timestamptz ELSE $4::timestamptz END
		WHERE id IN ($1,$2)`, parentID, childID, parentAt, childAt)
	must(t, err, "complete legacy envelope with distinct statement-era timestamps")
	return parentID, childID, parentAt, childAt
}

func assertLegacyEnvelopeCompletionClassification(t *testing.T, ctx context.Context, pool *pgxpool.Pool, parentID, childID uuid.UUID, parentAt, childAt time.Time) {
	t.Helper()
	var parentBound, childBound bool
	var verifierWouldReject bool
	var parentEffective, parentCompleted, childEffective, childCompleted time.Time
	must(t, pool.QueryRow(ctx, `SELECT
		parent.completion_effective_at_bound, parent.completion_effective_at, parent.completed_at,
		child.completion_effective_at_bound, child.completion_effective_at, child.completed_at,
		CASE
		  WHEN parent.completion_effective_at_bound THEN
		    child.completion_effective_at IS DISTINCT FROM parent.completion_effective_at
		    OR child.completed_at IS DISTINCT FROM parent.completion_effective_at
		  ELSE
		    child.completion_effective_at IS NULL
		    OR child.completed_at IS DISTINCT FROM child.completion_effective_at
		END
	FROM documents parent JOIN documents child ON child.parent_envelope_id=parent.id
	WHERE parent.id=$1 AND child.id=$2`, parentID, childID,
	).Scan(&parentBound, &parentEffective, &parentCompleted, &childBound, &childEffective, &childCompleted, &verifierWouldReject), "read legacy envelope completion classification")
	if parentBound || childBound || !parentEffective.Equal(parentAt) || !parentCompleted.Equal(parentAt) ||
		!childEffective.Equal(childAt) || !childCompleted.Equal(childAt) || parentEffective.Equal(childEffective) || verifierWouldReject {
		t.Fatalf("legacy envelope completion classification = parent(bound:%v effective:%s completed:%s) child(bound:%v effective:%s completed:%s)",
			parentBound, parentEffective, parentCompleted, childBound, childEffective, childCompleted)
	}
}

func assertCompletionClassifications(t *testing.T, ctx context.Context, pool *pgxpool.Pool, historicalID, activeID uuid.UUID, historicalCompletedAt time.Time) {
	t.Helper()
	var historicalBound bool
	var historicalEffective time.Time
	must(t, pool.QueryRow(ctx,
		`SELECT completion_effective_at_bound, completion_effective_at
		 FROM documents WHERE id = $1`, historicalID,
	).Scan(&historicalBound, &historicalEffective), "read historical completion classification")
	if historicalBound || !historicalEffective.Equal(historicalCompletedAt) {
		t.Fatalf("historical completion classification = bound:%v at:%s, want legacy-unbound at %s", historicalBound, historicalEffective, historicalCompletedAt)
	}
	var activeBound bool
	var activeEffective *time.Time
	must(t, pool.QueryRow(ctx,
		`SELECT completion_effective_at_bound, completion_effective_at
		 FROM documents WHERE id = $1`, activeID,
	).Scan(&activeBound, &activeEffective), "read active completion classification")
	if !activeBound || activeEffective != nil {
		t.Fatalf("active document classification = bound:%v at:%v, want bound with no timestamp", activeBound, activeEffective)
	}
}
