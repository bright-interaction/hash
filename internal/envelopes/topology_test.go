// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package envelopes

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/bright-interaction/hash/internal/db/generated"
)

type reorderDB struct {
	tag   pgconn.CommandTag
	err   error
	calls int
}

func (db *reorderDB) Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
	db.calls++
	return db.tag, db.err
}

func (*reorderDB) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, errors.New("unexpected query")
}

func (*reorderDB) QueryRow(context.Context, string, ...interface{}) pgx.Row {
	panic("unexpected query row")
}

func TestReorderRejectsZeroAffectedRows(t *testing.T) {
	db := &reorderDB{tag: pgconn.NewCommandTag("UPDATE 0")}
	engine := New(generated.New(db))

	err := engine.Reorder(
		context.Background(),
		uuid.New(),
		uuid.New(),
		[]uuid.UUID{uuid.New()},
	)
	if err == nil {
		t.Fatal("Reorder returned success after the guarded query affected zero rows")
	}
	if !strings.Contains(err.Error(), "not in this draft envelope") {
		t.Fatalf("unexpected error: %v", err)
	}
	if db.calls != 1 {
		t.Fatalf("Exec calls = %d, want 1", db.calls)
	}
}

func TestReorderAcceptsOneAffectedRow(t *testing.T) {
	db := &reorderDB{tag: pgconn.NewCommandTag("UPDATE 1")}
	engine := New(generated.New(db))

	err := engine.Reorder(
		context.Background(),
		uuid.New(),
		uuid.New(),
		[]uuid.UUID{uuid.New()},
	)
	if err != nil {
		t.Fatalf("Reorder returned error after one affected row: %v", err)
	}
}
