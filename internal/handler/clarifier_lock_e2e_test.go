// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/audit"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// The clarifier keeps this lock across a bounded provider call. FOR SHARE must
// block resend's UPDATE while remaining compatible with the foreign-key
// KEY SHARE locks taken by the independently durable event and AI audit rows.
// A FOR UPDATE implementation would make the two successful inserts below
// block on the clarifier's own document lock.
func TestClarifierShareLockFreezesEpochWithoutBlockingDurableAuditsE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	migrationDB := stdlib.OpenDB(*config.ConnConfig)
	if err := mdb.RunMigrations(migrationDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_ = migrationDB.Close()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	q := generated.New(pool)

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "clarifier lock " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uuid.NewString() + "@clarifier.test", Name: "Sender", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: org.ID, Name: "clarifier lock", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`),
		VariablesJson: json.RawMessage(`{}`), SenderID: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	lockTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lockTx.Rollback(context.Background()) }()
	if _, err := q.WithTx(lockTx).GetDocumentForShare(ctx, generated.GetDocumentForShareParams{ID: doc.ID, OrgID: org.ID}); err != nil {
		t.Fatalf("acquire clarifier share lock: %v", err)
	}

	boundedCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := audit.New(q, pool).Log(boundedCtx, audit.Entry{
		OrgID: org.ID, DocumentID: &doc.ID, Kind: "clarifier.requested", Payload: map[string]any{"test": true},
	}); err != nil {
		t.Fatalf("durable event blocked by clarifier share lock: %v", err)
	}
	if _, err := q.InsertAICompletionAudit(boundedCtx, generated.InsertAICompletionAuditParams{
		OrgID: org.ID, DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true},
		Provider: "test", Model: "test", PromptName: "signer_clarifier",
		Success: true, TransferJurisdiction: "local",
	}); err != nil {
		t.Fatalf("AI completion audit blocked by clarifier share lock: %v", err)
	}

	updateTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := updateTx.Exec(ctx, `SET LOCAL lock_timeout = '150ms'`); err != nil { //nolint:rawsql
		_ = updateTx.Rollback(ctx)
		t.Fatal(err)
	}
	_, updateErr := updateTx.Exec(ctx, `UPDATE documents SET updated_at = clock_timestamp() WHERE id = $1`, doc.ID) //nolint:rawsql
	_ = updateTx.Rollback(ctx)
	var pgErr *pgconn.PgError
	if !errors.As(updateErr, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("document update was not blocked by clarifier share lock: %v", updateErr)
	}

	if err := lockTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE documents SET updated_at = clock_timestamp() WHERE id = $1`, doc.ID); err != nil { //nolint:rawsql
		t.Fatalf("document update remained blocked after clarifier lock release: %v", err)
	}
}
