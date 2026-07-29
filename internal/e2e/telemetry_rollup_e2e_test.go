// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package e2e

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/telemetry"
)

// TestTelemetryRollupExactlyOnce is the regression guard for audit 2026-07-28
// finding H1 (engagement rollup double-counts) and for the two defects the
// round-1 fix for it introduced.
//
// It asserts four things against a real Postgres, driving the real tick body
// (internal/telemetry.RunRollupOnce) and the real goose migrations:
//
//  1. Repeated ticks over an unchanged event set do not inflate. This is the
//     original bug: an unwindowed SUM fed into an additive ON CONFLICT made a
//     true 40 read as 180 after 8 ticks.
//  2. Migration 00041 REPAIRS rows the old code already corrupted, including
//     on documents that have gone quiet and would never be revisited by a
//     forward-only fix, and it keeps a verbatim copy of every pre-fix row.
//  3. Totals do not DECAY when the 90-day prune deletes the raw rows that
//     produced them. A recompute-and-replace rollup sitting next to the prune
//     turned total_views into a shrinking 90-day counter and destroyed the
//     pruned events; accumulate-what-you-claimed does not.
//  4. A recipient-supplied dwell_ms that is not a number, or is absurdly
//     large, cannot freeze a document's rollup.
//
// It runs in the `e2e` job of .github/workflows/hash-ci.yml and, more
// importantly, in the `e2e` step of the real deploy gate
// (ci/userworkflows/deploy_hash.go, runHashE2E), both of which run
// `go test -tags e2e ./internal/e2e/...` with HASH_E2E_DB_URL pointing at a
// service container.
//
// The test creates and drops its OWN database on that server, so it neither
// depends on nor disturbs the shared e2e schema.
func TestTelemetryRollupExactlyOnce(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()

	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	q := generated.New(pool)

	// ---------------------------------------------------------------- seed
	// Schema as it stood BEFORE the repair migration, so the corrupted rows
	// can be seeded exactly as the broken worker would have left them.
	docA := seedDocument(t, ctx, q, "Active AB")
	docB := seedDocument(t, ctx, q, "Dormant AB")

	// docA: 5 honest views of blk-a at 1000ms, plus one event whose
	// recipient-supplied dwell_ms is a string. True lifetime: 6 views, 5000ms.
	for i := 0; i < 5; i++ {
		insertView(t, ctx, pool, docA, "blk-a", `{"dwell_ms":1000}`, time.Now().Add(-2*time.Hour))
	}
	insertView(t, ctx, pool, docA, "blk-a", `{"dwell_ms":"not-a-number"}`, time.Now().Add(-2*time.Hour))

	// docB went quiet 30 days ago: no traffic in the last 25h, so the old
	// 25h-window rollup would never visit it again. True lifetime: 3 views.
	for i := 0; i < 3; i++ {
		insertView(t, ctx, pool, docB, "blk-b", `{"dwell_ms":2000}`, time.Now().Add(-30*24*time.Hour))
	}

	// The damage the broken additive rollup left behind.
	seedSummary(t, ctx, pool, docA, "blk-a", 180, 180000)
	seedSummary(t, ctx, pool, docB, "blk-b", 900, 900000)
	// A row whose raw events are already gone, so it cannot be recomputed.
	seedSummary(t, ctx, pool, docB, "blk-gone", 77, 77000)

	// ------------------------------------------------------------- backfill
	migConn := stdlibConn(t, pool)
	must(t, mdb.RunMigrations(migConn), "run migrations (00041 backfill)")
	_ = migConn.Close()

	views, dwell := readSummary(t, ctx, pool, docA, "blk-a")
	if views != 6 || dwell != 5000 {
		t.Fatalf("backfill did not repair the active document: got %d views / %d ms, want 6 / 5000", views, dwell)
	}
	views, dwell = readSummary(t, ctx, pool, docB, "blk-b")
	if views != 3 || dwell != 6000 {
		t.Fatalf("backfill did not repair the DORMANT document (this is the forward-only-fix defect): got %d views / %d ms, want 3 / 6000", views, dwell)
	}
	if exists(t, ctx, pool, `SELECT 1 FROM document_engagement_summary WHERE document_id = $1 AND block_id = 'blk-gone'`, docB) {
		t.Fatalf("unrecoverable row was left in the live table with its inflated value")
	}
	if !exists(t, ctx, pool, `SELECT 1 FROM document_engagement_summary_h1_backup WHERE document_id = $1 AND block_id = 'blk-gone' AND total_views = 77`, docB) {
		t.Fatalf("unrecoverable row was dropped without a verbatim backup copy")
	}
	if !exists(t, ctx, pool, `SELECT 1 FROM document_engagement_summary_h1_backup WHERE document_id = $1 AND block_id = 'blk-a' AND total_views = 180`, docA) {
		t.Fatalf("pre-fix value of a repaired row was not preserved in the backup table")
	}

	// ------------------------------------------------------- no double count
	// The original H1 repro. Pre-fix, three ticks over an unchanged event set
	// took blk-a from 6 to 24 and kept climbing.
	for i := 0; i < 3; i++ {
		telemetry.RunRollupOnce(ctx, q, 90*24*time.Hour)
	}
	views, dwell = readSummary(t, ctx, pool, docA, "blk-a")
	if views != 6 || dwell != 5000 {
		t.Fatalf("rollup double-counted an already-rolled-up event set: got %d views / %d ms after 3 ticks, want 6 / 5000", views, dwell)
	}
	views, dwell = readSummary(t, ctx, pool, docB, "blk-b")
	if views != 3 || dwell != 6000 {
		t.Fatalf("dormant document changed under repeated ticks: got %d views / %d ms, want 3 / 6000", views, dwell)
	}

	// ------------------------------------------------------ genuine increment
	for i := 0; i < 4; i++ {
		insertView(t, ctx, pool, docA, "blk-a", `{"dwell_ms":1500}`, time.Now())
	}
	telemetry.RunRollupOnce(ctx, q, 90*24*time.Hour)
	views, dwell = readSummary(t, ctx, pool, docA, "blk-a")
	if views != 10 || dwell != 11000 {
		t.Fatalf("new events were not accumulated exactly once: got %d views / %d ms, want 10 / 11000", views, dwell)
	}
	telemetry.RunRollupOnce(ctx, q, 90*24*time.Hour)
	views, dwell = readSummary(t, ctx, pool, docA, "blk-a")
	if views != 10 || dwell != 11000 {
		t.Fatalf("replaying the tick re-counted the new events: got %d views / %d ms, want 10 / 11000", views, dwell)
	}

	// ----------------------------------------------------- prune does not eat
	// 7 views that are already past the 90-day retention edge. The tick must
	// count them on the way out and must not revise the total downward on the
	// next tick once the raw rows are gone.
	oldEventAt := time.Now().Add(-100 * 24 * time.Hour)
	for i := 0; i < 7; i++ {
		insertView(t, ctx, pool, docA, "blk-old", `{"dwell_ms":100}`, oldEventAt)
	}
	telemetry.RunRollupOnce(ctx, q, 90*24*time.Hour)
	views, dwell = readSummary(t, ctx, pool, docA, "blk-old")
	if views != 7 || dwell != 700 {
		t.Fatalf("events at the retention edge were not counted before the prune: got %d views / %d ms, want 7 / 700", views, dwell)
	}
	if exists(t, ctx, pool, `SELECT 1 FROM telemetry_events WHERE document_id = $1 AND block_id = 'blk-old'`, docA) {
		t.Fatalf("prune did not delete the raw rows past retention, the decay repro is not actually exercised")
	}
	telemetry.RunRollupOnce(ctx, q, 90*24*time.Hour)
	views, dwell = readSummary(t, ctx, pool, docA, "blk-old")
	if views != 7 || dwell != 700 {
		t.Fatalf("total DECAYED after its raw rows were pruned: got %d views / %d ms, want 7 / 700", views, dwell)
	}
	// The aggregate still carries evidence the raw rows can no longer supply.
	var lastEventAt time.Time
	if err := pool.QueryRow(ctx, `SELECT last_event_at FROM document_engagement_summary WHERE document_id = $1 AND block_id = 'blk-old'`, docA).Scan(&lastEventAt); err != nil {
		t.Fatalf("read last_event_at: %v", err)
	}
	if time.Since(lastEventAt) < 90*24*time.Hour {
		t.Fatalf("last_event_at was not carried over from the pruned rows: got %s", lastEventAt)
	}

	// A prune that deletes nothing must still return a row, not sql.ErrNoRows:
	// the tick calls it every hour and almost always deletes nothing.
	empty, err := q.PruneTelemetryOlderThan(ctx, pgtype.Timestamptz{Time: time.Now().Add(-90 * 24 * time.Hour), Valid: true})
	must(t, err, "prune with nothing to delete")
	if empty.DeletedRows != 0 || empty.UnrolledViews != 0 {
		t.Fatalf("empty prune reported %d deleted / %d unrolled, want 0 / 0", empty.DeletedRows, empty.UnrolledViews)
	}

	// ------------------------------------------------- silent loss is loud
	// Rows that reach the retention edge unclaimed must be reported, not
	// dropped silently. Prune is called directly here so the rollup does not
	// claim them first.
	for i := 0; i < 2; i++ {
		insertView(t, ctx, pool, docA, "blk-unrolled", `{"dwell_ms":50}`, oldEventAt)
	}
	pruned, err := q.PruneTelemetryOlderThan(ctx, pgtype.Timestamptz{Time: time.Now().Add(-90 * 24 * time.Hour), Valid: true})
	must(t, err, "prune with unrolled rows past retention")
	if pruned.UnrolledViews != 2 {
		t.Fatalf("prune did not report unrolled block.viewed rows: got %d, want 2", pruned.UnrolledViews)
	}

	// ----------------------------------------------------- poisoned payloads
	// A magic-link holder can POST any JSON. Neither a non-numeric nor an
	// out-of-range dwell_ms may abort the statement, which would freeze this
	// document's summary on every tick forever.
	docC := seedDocument(t, ctx, q, "Poison AB")
	insertView(t, ctx, pool, docC, "blk-p", `{"dwell_ms":"not-a-number"}`, time.Now())
	insertView(t, ctx, pool, docC, "blk-p", `{"dwell_ms":9223372036854775807}`, time.Now())
	insertView(t, ctx, pool, docC, "blk-p", `{"dwell_ms":500}`, time.Now())
	telemetry.RunRollupOnce(ctx, q, 90*24*time.Hour)
	views, dwell = readSummary(t, ctx, pool, docC, "blk-p")
	if views != 3 || dwell != 500 {
		t.Fatalf("poisoned dwell_ms broke the rollup: got %d views / %d ms, want 3 / 500", views, dwell)
	}
}

// scratchDatabase creates a throwaway database on the same server as dsn,
// migrates nothing, and returns a pool onto it plus a cleanup that closes the
// pool and drops the database. Shared state on the e2e server is untouched.
func scratchDatabase(t *testing.T, ctx context.Context, dsn string) (*pgxpool.Pool, func()) {
	t.Helper()
	name := "hash_h1_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]

	adminCfg, err := pgxpool.ParseConfig(dsn)
	must(t, err, "parse dsn")
	adminDB := stdlib.OpenDB(*adminCfg.ConnConfig)
	// The name is a fixed prefix plus hex from a generated UUID, so there is
	// nothing to inject; CREATE DATABASE cannot take an identifier parameter.
	_, err = adminDB.ExecContext(ctx, "CREATE DATABASE "+name) //nolint:rawsql
	must(t, err, "create scratch database")

	scratchCfg, err := pgxpool.ParseConfig(dsn)
	must(t, err, "parse dsn for scratch")
	scratchCfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, scratchCfg)
	must(t, err, "scratch pool")

	// Pre-00041 schema, so the corrupted rows this migration repairs can be
	// seeded the way the broken worker left them.
	migConn := stdlib.OpenDB(*scratchCfg.ConnConfig)
	must(t, mdb.RunMigrationsUpTo(migConn, 40), "run migrations up to 00040")
	_ = migConn.Close()

	return pool, func() {
		pool.Close()
		if _, err := adminDB.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil { //nolint:rawsql
			t.Logf("drop scratch database %s: %v", name, err)
		}
		_ = adminDB.Close()
	}
}

func stdlibConn(t *testing.T, pool *pgxpool.Pool) *sql.DB {
	t.Helper()
	return stdlib.OpenDB(*pool.Config().ConnConfig)
}

func seedDocument(t *testing.T, ctx context.Context, q *generated.Queries, orgName string) uuid.UUID {
	t.Helper()
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: orgName, Plan: "pro"})
	must(t, err, "create org")
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uuid.NewString() + "@e2e.example", Name: "Sender", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	must(t, err, "create user")
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: org.ID, Name: "Avtal", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`),
		VariablesJson: json.RawMessage(`{}`), SenderID: user.ID,
	})
	must(t, err, "create document")
	_, err = q.CreateRecipient(ctx, generated.CreateRecipientParams{
		DocumentID: doc.ID, Role: "signer", Email: "client@example.com", Name: "Client", OrderIndex: 0,
		MagicTokenHash:      []byte(uuid.NewString()),
		MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(72 * time.Hour), Valid: true},
		Locale:              "sv",
	})
	must(t, err, "create recipient")
	return doc.ID
}

// insertView writes a raw block.viewed event with an explicit created_at,
// which the generated insert cannot do (it takes the column default).
func insertView(t *testing.T, ctx context.Context, pool *pgxpool.Pool, docID uuid.UUID, blockID, payload string, at time.Time) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO telemetry_events (document_id, recipient_id, kind, block_id, payload_json, created_at)
		SELECT $1, r.id, 'block.viewed', $2, $3::jsonb, $4
		FROM recipients r WHERE r.document_id = $1 LIMIT 1`,
		docID, blockID, payload, at)
	must(t, err, "insert telemetry event")
}

// seedSummary writes the shape the broken additive rollup left on disk.
func seedSummary(t *testing.T, ctx context.Context, pool *pgxpool.Pool, docID uuid.UUID, blockID string, views int32, dwell int64) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO document_engagement_summary
			(document_id, block_id, total_views, total_dwell_ms, avg_dwell_ms, last_event_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, now(), now())`,
		docID, blockID, views, dwell, int32(dwell/int64(views)))
	must(t, err, "seed engagement summary")
}

func readSummary(t *testing.T, ctx context.Context, pool *pgxpool.Pool, docID uuid.UUID, blockID string) (int32, int64) {
	t.Helper()
	var views int32
	var dwell int64
	err := pool.QueryRow(ctx,
		`SELECT total_views, total_dwell_ms FROM document_engagement_summary WHERE document_id = $1 AND block_id = $2`,
		docID, blockID).Scan(&views, &dwell)
	must(t, err, fmt.Sprintf("read summary %s/%s", docID, blockID))
	return views, dwell
}

func exists(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) bool {
	t.Helper()
	var one int
	err := pool.QueryRow(ctx, query, args...).Scan(&one)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return false
		}
		t.Fatalf("exists query: %v", err)
	}
	return true
}
