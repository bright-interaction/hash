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

	if err := goose.Up(db, "migrations"); err != nil {
		return fmt.Errorf("run goose migrations: %w", err)
	}

	slog.Info("migrations applied")
	return nil
}
