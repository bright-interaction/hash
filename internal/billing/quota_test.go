// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

type quotaDB struct {
	planErr   error
	usageErr  error
	lockErr   error
	lockCalls int
	lockOrg   string
	docs      int64
	recs      int64
}

func (db *quotaDB) Exec(_ context.Context, query string, args ...interface{}) (pgconn.CommandTag, error) {
	if !strings.Contains(query, "LockBillingUsageForOrg") {
		return pgconn.CommandTag{}, errors.New("unexpected Exec")
	}
	db.lockCalls++
	if len(args) == 1 {
		db.lockOrg, _ = args[0].(string)
	}
	return pgconn.CommandTag{}, db.lockErr
}

func (*quotaDB) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query")
}

func (db *quotaDB) QueryRow(_ context.Context, query string, _ ...interface{}) pgx.Row {
	switch {
	case strings.Contains(query, "GetOrgSubscription"):
		return quotaRow{err: pgx.ErrNoRows}
	case strings.Contains(query, "GetBillingPlanBySlug"):
		if db.planErr != nil {
			return quotaRow{err: db.planErr}
		}
		return quotaRow{values: []any{
			uuid.New(), "free", "Free", "For trying Hash", int32(0), int32(0), "EUR",
			int32(5), int32(10), json.RawMessage(`{"aes":false}`), true, int32(10), pgtype.Timestamptz{},
		}}
	case strings.Contains(query, "CountBillingUsageInPeriodForOrg"):
		if db.usageErr != nil {
			return quotaRow{err: db.usageErr}
		}
		return quotaRow{values: []any{db.docs, db.recs}}
	default:
		return quotaRow{err: fmt.Errorf("unexpected query: %.80s", query)}
	}
}

type quotaRow struct {
	values []any
	err    error
}

func (row quotaRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != len(row.values) {
		return fmt.Errorf("scan destinations=%d values=%d", len(destinations), len(row.values))
	}
	for i := range destinations {
		reflect.ValueOf(destinations[i]).Elem().Set(reflect.ValueOf(row.values[i]))
	}
	return nil
}

func TestEnforceDocumentQuotaFailsClosedWhenPlanUnavailable(t *testing.T) {
	dbErr := errors.New("database unavailable")
	engine := New(generated.New(&quotaDB{planErr: dbErr}), MockProvider{}, "", "")
	err := engine.EnforceDocumentQuota(context.Background(), uuid.New())
	assertEntitlementUnavailable(t, err, dbErr)
}

func TestEnforceDocumentQuotaFailsClosedWhenUsageUnavailable(t *testing.T) {
	dbErr := errors.New("usage query unavailable")
	engine := New(generated.New(&quotaDB{usageErr: dbErr}), MockProvider{}, "", "")
	err := engine.EnforceDocumentQuota(context.Background(), uuid.New())
	assertEntitlementUnavailable(t, err, dbErr)
}

func TestEnforceDocumentQuotaEnforcesRecipientDimension(t *testing.T) {
	engine := New(generated.New(&quotaDB{docs: 5, recs: 11}), MockProvider{}, "", "")
	err := engine.EnforceDocumentQuota(context.Background(), uuid.New())
	if !errors.Is(err, ErrQuotaExceeded) || errors.Is(err, ErrEntitlementUnavailable) {
		t.Fatalf("quota error = %v, want known ErrQuotaExceeded", err)
	}
}

func TestEnforceDocumentQuotaAllowsExactPublishedLimits(t *testing.T) {
	engine := New(generated.New(&quotaDB{docs: 5, recs: 10}), MockProvider{}, "", "")
	if err := engine.EnforceDocumentQuota(context.Background(), uuid.New()); err != nil {
		t.Fatalf("exact plan limits should be allowed: %v", err)
	}
}

func TestLockDocumentQuotaMutationUsesSharedOrgLock(t *testing.T) {
	db := &quotaDB{}
	engine := New(generated.New(db), MockProvider{}, "", "")
	orgID := uuid.New()
	if err := engine.LockDocumentQuotaMutation(context.Background(), generated.New(db), orgID); err != nil {
		t.Fatal(err)
	}
	if db.lockCalls != 1 || db.lockOrg != orgID.String() {
		t.Fatalf("lock calls=%d org=%q, want one call for %q", db.lockCalls, db.lockOrg, orgID)
	}
}

func TestLockDocumentQuotaMutationFailsClosed(t *testing.T) {
	dbErr := errors.New("lock unavailable")
	db := &quotaDB{lockErr: dbErr}
	engine := New(generated.New(db), MockProvider{}, "", "")
	err := engine.LockDocumentQuotaMutation(context.Background(), generated.New(db), uuid.New())
	assertEntitlementUnavailable(t, err, dbErr)
}

func TestEnforceDocumentQuotaMutationReadsFromSuppliedTransaction(t *testing.T) {
	originalErr := errors.New("non-transactional query set must not be used")
	engine := New(generated.New(&quotaDB{planErr: originalErr}), MockProvider{}, "", "")
	txDB := &quotaDB{docs: 5, recs: 10}
	if err := engine.EnforceDocumentQuotaMutation(context.Background(), generated.New(txDB), uuid.New()); err != nil {
		t.Fatalf("transaction-bound quota enforcement failed: %v", err)
	}
}

func TestQuotaMutationHelpersFailClosedWithMissingTransactionQueries(t *testing.T) {
	engine := New(generated.New(&quotaDB{}), MockProvider{}, "", "")
	for _, err := range []error{
		engine.LockDocumentQuotaMutation(context.Background(), nil, uuid.New()),
		engine.EnforceDocumentQuotaMutation(context.Background(), nil, uuid.New()),
	} {
		if !errors.Is(err, ErrEntitlementUnavailable) {
			t.Fatalf("missing transaction dependency error = %v, want ErrEntitlementUnavailable", err)
		}
	}
}

func TestQuotaMutationHelpersAreNoOpWhenBillingIsDisabled(t *testing.T) {
	var engine *Engine
	if err := engine.LockDocumentQuotaMutation(context.Background(), nil, uuid.Nil); err != nil {
		t.Fatalf("disabled billing lock = %v, want nil", err)
	}
	if err := engine.EnforceDocumentQuotaMutation(context.Background(), nil, uuid.Nil); err != nil {
		t.Fatalf("disabled billing enforcement = %v, want nil", err)
	}
}

func assertEntitlementUnavailable(t *testing.T, err, cause error) {
	t.Helper()
	if !errors.Is(err, ErrEntitlementUnavailable) || errors.Is(err, ErrQuotaExceeded) || !errors.Is(err, cause) {
		t.Fatalf("error = %v, want typed entitlement unavailable wrapping %v", err, cause)
	}
	var typed *EntitlementUnavailableError
	if !errors.As(err, &typed) {
		t.Fatalf("error type = %T, want *EntitlementUnavailableError", err)
	}
}
