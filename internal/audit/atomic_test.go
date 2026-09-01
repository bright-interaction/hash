// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/bright-interaction/hash/internal/db/generated"
)

type atomicTestBeginner struct{ tx *atomicTestTx }

func (b atomicTestBeginner) Begin(context.Context) (pgx.Tx, error) { return b.tx, nil }

type atomicTestAppender struct {
	err       error
	logged    bool
	published bool
	committed *bool
}

func (a *atomicTestAppender) LogTx(context.Context, pgx.Tx, Entry) (PendingEvent, error) {
	a.logged = true
	return PendingEvent{ID: uuid.New()}, a.err
}

func (a *atomicTestAppender) Publish(PendingEvent) {
	if a.committed == nil || !*a.committed {
		panic("audit event published before commit")
	}
	a.published = true
}

type atomicTestTx struct {
	committed  bool
	rolledBack bool
}

func (tx *atomicTestTx) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("unexpected nested begin")
}
func (tx *atomicTestTx) Commit(context.Context) error { tx.committed = true; return nil }
func (tx *atomicTestTx) Rollback(context.Context) error {
	if !tx.committed {
		tx.rolledBack = true
	}
	return nil
}
func (*atomicTestTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("unexpected copy")
}
func (*atomicTestTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults { return nil }
func (*atomicTestTx) LargeObjects() pgx.LargeObjects                         { return pgx.LargeObjects{} }
func (*atomicTestTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("unexpected prepare")
}
func (*atomicTestTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("unexpected exec")
}
func (*atomicTestTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected query")
}
func (*atomicTestTx) QueryRow(context.Context, string, ...any) pgx.Row { return atomicTestRow{} }
func (*atomicTestTx) Conn() *pgx.Conn                                  { return nil }

type atomicTestRow struct{}

func (atomicTestRow) Scan(...any) error { return errors.New("unexpected query row") }

func TestCommitMutationRollsBackWhenAuditAppendFails(t *testing.T) {
	tx := &atomicTestTx{}
	appendErr := errors.New("audit unavailable")
	logger := &atomicTestAppender{err: appendErr, committed: &tx.committed}
	mutated := false

	value, err := CommitMutation(context.Background(), atomicTestBeginner{tx: tx}, logger,
		func(*generated.Queries) (string, error) {
			mutated = true
			return "one-time-plaintext", nil
		},
		func(string) Entry { return Entry{OrgID: uuid.New(), Kind: "credential.created"} },
	)
	if !errors.Is(err, appendErr) {
		t.Fatalf("error = %v, want wrapped audit failure", err)
	}
	if value != "" {
		t.Fatalf("returned value = %q; plaintext must not escape a failed audit transaction", value)
	}
	if !mutated || !logger.logged {
		t.Fatal("mutation and audit append should both have been attempted")
	}
	if tx.committed || !tx.rolledBack || logger.published {
		t.Fatalf("committed=%v rolled_back=%v published=%v, want false/true/false", tx.committed, tx.rolledBack, logger.published)
	}
}

func TestCommitMutationReturnsValueOnlyAfterCommitAndPublish(t *testing.T) {
	tx := &atomicTestTx{}
	logger := &atomicTestAppender{committed: &tx.committed}
	value, err := CommitMutation(context.Background(), atomicTestBeginner{tx: tx}, logger,
		func(*generated.Queries) (string, error) { return "one-time-plaintext", nil },
		func(string) Entry { return Entry{OrgID: uuid.New(), Kind: "credential.created"} },
	)
	if err != nil {
		t.Fatal(err)
	}
	if value != "one-time-plaintext" || !tx.committed || tx.rolledBack || !logger.published {
		t.Fatalf("value=%q committed=%v rolled_back=%v published=%v", value, tx.committed, tx.rolledBack, logger.published)
	}
}

func TestCommitMutationRollsBackNonexistentRowWithoutFalseAudit(t *testing.T) {
	tx := &atomicTestTx{}
	logger := &atomicTestAppender{committed: &tx.committed}
	value, err := CommitMutation(context.Background(), atomicTestBeginner{tx: tx}, logger,
		func(*generated.Queries) (uuid.UUID, error) { return uuid.Nil, pgx.ErrNoRows },
		func(uuid.UUID) Entry { return Entry{OrgID: uuid.New(), Kind: "credential.revoked"} },
	)
	if !errors.Is(err, pgx.ErrNoRows) || value != uuid.Nil {
		t.Fatalf("value=%s error=%v, want zero and pgx.ErrNoRows", value, err)
	}
	if !tx.rolledBack || tx.committed || logger.logged || logger.published {
		t.Fatalf("committed=%v rolled_back=%v logged=%v published=%v", tx.committed, tx.rolledBack, logger.logged, logger.published)
	}
}
