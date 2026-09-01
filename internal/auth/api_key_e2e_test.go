// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestClaimDocAgentTokenUseAllowsExactlyOneConcurrentUseE2E(t *testing.T) {
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

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "token claim " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uuid.NewString() + "@token.test", Name: "Token Owner", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: org.ID, Name: "token claim", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`),
		VariablesJson: json.RawMessage(`{}`), SenderID: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := q.InsertDocAgentToken(ctx, generated.InsertDocAgentTokenParams{
		DocumentID: doc.ID, OrgID: org.ID, Name: "one use", Prefix: uuid.NewString()[:8],
		KeyHash: make([]byte, 32), Scopes: []string{"read"}, CreatedBy: pgtype.UUID{Bytes: user.ID, Valid: true},
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, MaxUses: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 2
	errorsByAttempt := make(chan error, attempts)
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(attempts)
	for range attempts {
		go func() {
			ready.Done()
			<-start
			_, claimErr := q.ClaimDocAgentTokenUse(ctx, token.ID)
			errorsByAttempt <- claimErr
		}()
	}
	ready.Wait()
	close(start)

	succeeded, exhausted := 0, 0
	for range attempts {
		err := <-errorsByAttempt
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, pgx.ErrNoRows):
			exhausted++
		default:
			t.Fatalf("unexpected claim error: %v", err)
		}
	}
	if succeeded != 1 || exhausted != 1 {
		t.Fatalf("concurrent claims succeeded/exhausted = %d/%d, want 1/1", succeeded, exhausted)
	}
	fresh, err := q.GetDocAgentTokenByPrefix(ctx, token.Prefix)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.UsedCount != 1 || !fresh.LastUsedAt.Valid {
		t.Fatalf("claimed token used_count/last_used_at = %d/%v, want 1/valid", fresh.UsedCount, fresh.LastUsedAt.Valid)
	}
}
