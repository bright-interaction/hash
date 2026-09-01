// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package audit

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// TxBeginner is implemented by pgxpool.Pool. Keeping the boundary small also
// lets the atomicity contract be exercised without a live database.
type TxBeginner interface {
	Begin(context.Context) (pgx.Tx, error)
}

// TxAppender is the transaction-aware portion of Logger used by CommitMutation.
// The event is published to hooks only after the caller's transaction commits.
type TxAppender interface {
	LogTx(context.Context, pgx.Tx, Entry) (PendingEvent, error)
	Publish(PendingEvent)
}

// CommitMutation runs a security/accountability-sensitive database mutation and
// its audit-chain append in one transaction. The mutated value is returned only
// after both writes commit, which is important for one-time plaintext secrets:
// callers must never disclose a credential whose creation was not audited.
func CommitMutation[T any](ctx context.Context, beginner TxBeginner, logger TxAppender,
	mutate func(*generated.Queries) (T, error), event func(T) Entry,
) (T, error) {
	var zero T
	if nilInterface(beginner) || nilInterface(logger) || mutate == nil || event == nil {
		return zero, errors.New("atomic audited mutation: dependencies unavailable")
	}
	tx, err := beginner.Begin(ctx)
	if err != nil {
		return zero, fmt.Errorf("atomic audited mutation: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	value, err := mutate(generated.New(tx))
	if err != nil {
		return zero, err
	}
	pending, err := logger.LogTx(ctx, tx, event(value))
	if err != nil {
		return zero, fmt.Errorf("atomic audited mutation: append audit event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return zero, fmt.Errorf("atomic audited mutation: commit: %w", err)
	}
	logger.Publish(pending)
	return value, nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
