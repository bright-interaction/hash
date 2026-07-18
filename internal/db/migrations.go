// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package db wires the embedded goose migrations and exposes a runner.
package db

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"

	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

// RunMigrations applies pending Postgres migrations using goose against the
// caller-provided *sql.DB. Every migration in this directory MUST start with
// the `-- +goose Up` directive ,  the dockyard outage on 2026-05-09 was caused
// by a migration that omitted it.
func RunMigrations(db *sql.DB) error {
	goose.SetBaseFS(embeddedMigrations)

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set goose dialect: %w", err)
	}

	// Serialize concurrent migrators. The server and the worker both call this
	// on boot and docker-compose.prod.yml has no depends_on ordering between
	// them, so on a `compose up` recreate they would race goose.Up into a
	// "relation already exists" crash-loop (the migrations use no IF NOT EXISTS).
	// A session advisory lock makes the loser wait for the winner instead. The
	// key is an arbitrary constant shared by every instance.
	const migrateLockKey = int64(792310457018)                                        // "hash migrations"
	if _, err := db.Exec("SELECT pg_advisory_lock($1)", migrateLockKey); err != nil { //nolint:rawsql
		return fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer func() { _, _ = db.Exec("SELECT pg_advisory_unlock($1)", migrateLockKey) }() //nolint:rawsql

	if err := goose.Up(db, "migrations"); err != nil {
		return fmt.Errorf("run goose migrations: %w", err)
	}

	slog.Info("migrations applied")
	return nil
}
