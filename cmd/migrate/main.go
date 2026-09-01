// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Command migrate applies Hash's embedded database migrations and exits. The
// production release workflow runs this exact candidate-image binary only
// after its fresh-backup/old-image compatibility gate has passed, allowing the
// complete audit chain to be verified before any traffic moves to the release.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	mdb "github.com/bright-interaction/hash/internal/db"
)

func main() {
	if err := run(context.Background(), os.Getenv("HASH_DB_URL")); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "hash-migrate:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, dsn string) error {
	if dsn == "" {
		return fmt.Errorf("HASH_DB_URL is required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// A parser error can quote its input. Do not copy a credential-bearing
		// URL into release logs.
		return fmt.Errorf("HASH_DB_URL is invalid")
	}
	db := stdlib.OpenDB(*cfg.ConnConfig)
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	if err := mdb.RunMigrations(db); err != nil {
		return fmt.Errorf("apply embedded migrations: %w", err)
	}
	return nil
}
