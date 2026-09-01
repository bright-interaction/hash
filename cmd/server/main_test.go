// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

type fakeProductionLease struct {
	rows     []pgx.Row
	queries  []string
	args     [][]any
	released bool
}

func TestRuntimeOperatorIdentityIsWiredThroughEveryPublicArtifact(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, required := range []string{
		"OrgName:      cfg.OperatorName",
		`Issuer:                       "Hash / " + cfg.OperatorName`,
		"OrgName:   cfg.OperatorName",
		"renderEmailForMCP(cfg.OperatorName)",
		"OperatorName:               cfg.OperatorName",
		"PrivacyContact:             cfg.PrivacyContact",
		"SupervisoryAuthority:       cfg.SupervisoryAuthority",
	} {
		if !strings.Contains(src, required) {
			t.Errorf("server runtime lacks operator identity wiring %q", required)
		}
	}
	for _, forbidden := range []string{`OrgName:      "Bright Interaction"`, `Issuer:                       "Hash / Bright Interaction AB"`} {
		if strings.Contains(src, forbidden) {
			t.Errorf("server runtime retains vendor-specific self-host identity %q", forbidden)
		}
	}
}

func (l *fakeProductionLease) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	l.queries = append(l.queries, query)
	l.args = append(l.args, args)
	if len(l.rows) == 0 {
		return fakeProductionLeaseRow{err: errors.New("unexpected query")}
	}
	row := l.rows[0]
	l.rows = l.rows[1:]
	return row
}

func (l *fakeProductionLease) Release() { l.released = true }

type fakeProductionLeaseRow struct {
	value any
	err   error
}

func (r fakeProductionLeaseRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 1 {
		return errors.New("fake lease row requires one destination")
	}
	switch value := r.value.(type) {
	case bool:
		out, ok := dest[0].(*bool)
		if !ok {
			return errors.New("fake lease row bool destination mismatch")
		}
		*out = value
	case int:
		out, ok := dest[0].(*int)
		if !ok {
			return errors.New("fake lease row int destination mismatch")
		}
		*out = value
	default:
		return errors.New("unsupported fake lease row value")
	}
	return nil
}

func TestEvidenceTrustedPublicKeysIncludesCurrentAndUniqueHistoricalKeys(t *testing.T) {
	got := evidenceTrustedPublicKeys("current", "old-1, current,old-2,old-1")
	want := []string{"current", "old-1", "old-2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("trusted evidence keys = %v, want %v", got, want)
	}
}

func TestServerPoolConfigReservesClarifierAndProductionLeaseConnections(t *testing.T) {
	const base = "postgres://hash:test@localhost:5432/hash?sslmode=disable&pool_max_conns="
	for _, tc := range []struct {
		name        string
		environment string
		maxConns    string
		wantError   bool
	}{
		{name: "development rejects one", environment: "development", maxConns: "1", wantError: true},
		{name: "development accepts two", environment: "development", maxConns: "2"},
		{name: "production rejects two", environment: "production", maxConns: "2", wantError: true},
		{name: "production accepts three", environment: "production", maxConns: "3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := serverPoolConfig(base+tc.maxConns, tc.environment)
			if tc.wantError {
				if err == nil || cfg != nil || !strings.Contains(err.Error(), "requires at least") {
					t.Fatalf("serverPoolConfig = (%v, %v), want minimum-size error", cfg, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("serverPoolConfig: %v", err)
			}
			if cfg == nil || cfg.MaxConns != int32(tc.maxConns[0]-'0') {
				t.Fatalf("pool config = %#v, want max %s", cfg, tc.maxConns)
			}
		})
	}
}

func TestAcquireProductionServerLeaseFailsClosedWhenAlreadyHeld(t *testing.T) {
	lease := &fakeProductionLease{rows: []pgx.Row{fakeProductionLeaseRow{value: false}}}
	got, err := acquireProductionServerLease(context.Background(), func(context.Context) (productionServerLease, error) {
		return lease, nil
	})
	if got != nil {
		t.Fatal("second production server received a lease")
	}
	if err == nil || !strings.Contains(err.Error(), "another production Hash HTTP server") {
		t.Fatalf("second production server error = %v", err)
	}
	if !lease.released {
		t.Fatal("rejected production singleton connection was not released")
	}
	if len(lease.args) != 1 || len(lease.args[0]) != 1 || lease.args[0][0] != productionServerLockKey {
		t.Fatalf("advisory lock args = %#v, want singleton key %d", lease.args, productionServerLockKey)
	}
}

func TestAcquireProductionServerLeaseHoldsDedicatedConnection(t *testing.T) {
	lease := &fakeProductionLease{rows: []pgx.Row{fakeProductionLeaseRow{value: true}}}
	got, err := acquireProductionServerLease(context.Background(), func(context.Context) (productionServerLease, error) {
		return lease, nil
	})
	if err != nil {
		t.Fatalf("acquire production singleton lease: %v", err)
	}
	if got != lease {
		t.Fatal("acquired lease did not retain the dedicated connection")
	}
	if lease.released {
		t.Fatal("successful production singleton connection was released early")
	}
	got.Release()
	if !lease.released {
		t.Fatal("successful production singleton connection was not releasable")
	}
}

func TestAcquireProductionServerLeaseReleasesOnDatabaseError(t *testing.T) {
	lease := &fakeProductionLease{rows: []pgx.Row{fakeProductionLeaseRow{err: errors.New("database unavailable")}}}
	got, err := acquireProductionServerLease(context.Background(), func(context.Context) (productionServerLease, error) {
		return lease, nil
	})
	if got != nil || err == nil || !strings.Contains(err.Error(), "database unavailable") {
		t.Fatalf("database failure result = (%v, %v)", got, err)
	}
	if !lease.released {
		t.Fatal("failed production singleton connection was not released")
	}
}

func TestVerifyProductionServerLeaseFailsWhenSessionIsLost(t *testing.T) {
	healthy := &fakeProductionLease{rows: []pgx.Row{fakeProductionLeaseRow{value: 1}}}
	if err := verifyProductionServerLease(context.Background(), healthy); err != nil {
		t.Fatalf("healthy production singleton lease rejected: %v", err)
	}

	lost := &fakeProductionLease{rows: []pgx.Row{fakeProductionLeaseRow{err: errors.New("connection closed")}}}
	if err := verifyProductionServerLease(context.Background(), lost); err == nil || !strings.Contains(err.Error(), "connection closed") {
		t.Fatalf("lost production singleton lease error = %v", err)
	}
}
