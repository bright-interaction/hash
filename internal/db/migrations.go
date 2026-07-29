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
	return migrate(db, 0)
}

// RunMigrationsUpTo applies pending migrations only as far as `version`
// (inclusive). It exists so a test can stand up the schema as it was BEFORE a
// data-repair migration, seed the corrupted rows that migration is meant to
// repair, and then let the real migration run over them. Production callers
// want RunMigrations.
func RunMigrationsUpTo(db *sql.DB, version int64) error {
	return migrate(db, version)
}

// migrate runs goose Up, or UpTo when version > 0.
func migrate(db *sql.DB, version int64) error {
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

	if version > 0 {
		if err := goose.UpTo(db, "migrations", version); err != nil {
			return fmt.Errorf("run goose migrations up to %d: %w", version, err)
		}
		slog.Info("migrations applied", "up_to", version)
		return nil
	}

	if err := goose.Up(db, "migrations"); err != nil {
		return fmt.Errorf("run goose migrations: %w", err)
	}

	slog.Info("migrations applied")
	return nil
}
