// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package e2e

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestOIDCIdentityBindingIsCasefoldedAndOneWayE2E(t *testing.T) {
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

	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "OIDC binding " + uuid.NewString(), Plan: "starter"})
	if err != nil {
		t.Fatal(err)
	}
	localPart := strings.ReplaceAll(uuid.NewString(), "-", "")
	email := localPart + "@OIDC.Example"
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: email, Name: "Invited Owner", Role: "owner", ZitadelSub: pgtype.Text{},
	})
	if err != nil {
		t.Fatal(err)
	}

	byEmail, err := q.GetUserByEmail(ctx, strings.ToLower(email))
	if err != nil || byEmail.ID != user.ID {
		t.Fatalf("casefolded lookup = %#v, %v", byEmail, err)
	}

	subjects := []string{"oidc-a-" + uuid.NewString(), "oidc-b-" + uuid.NewString()}
	results := make(chan struct {
		subject string
		user    *generated.User
		err     error
	}, len(subjects))
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(len(subjects))
	for _, subject := range subjects {
		subject := subject
		go func() {
			ready.Done()
			<-start
			bound, bindErr := q.BindUserZitadelSub(ctx, generated.BindUserZitadelSubParams{
				ID: user.ID, ZitadelSub: pgtype.Text{String: subject, Valid: true},
			})
			results <- struct {
				subject string
				user    *generated.User
				err     error
			}{subject: subject, user: bound, err: bindErr}
		}()
	}
	ready.Wait()
	close(start)

	winner := ""
	for range subjects {
		result := <-results
		switch {
		case result.err == nil:
			if winner != "" || result.user == nil || !result.user.ZitadelSub.Valid || result.user.ZitadelSub.String != result.subject {
				t.Fatalf("invalid binding winner: %#v", result)
			}
			winner = result.subject
		case errors.Is(result.err, pgx.ErrNoRows):
		default:
			t.Fatalf("unexpected binding result: %#v", result)
		}
	}
	if winner == "" {
		t.Fatal("concurrent first binding had no winner")
	}
	if _, err := q.BindUserZitadelSub(ctx, generated.BindUserZitadelSubParams{
		ID: user.ID, ZitadelSub: pgtype.Text{String: winner, Valid: true},
	}); err != nil {
		t.Fatalf("idempotent repeat binding: %v", err)
	}

	_, err = q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: strings.ToUpper(email), Name: "Case Duplicate", Role: "sender",
		ZitadelSub: pgtype.Text{String: "other-" + uuid.NewString(), Valid: true},
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("casefolded duplicate create error = %v, want unique violation", err)
	}
}
