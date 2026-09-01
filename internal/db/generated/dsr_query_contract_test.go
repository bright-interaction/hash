// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package generated

import (
	"os"
	"strings"
	"testing"
)

func TestDSRTransitionQueriesAreLockingAndCompareAndSwap(t *testing.T) {
	raw, err := os.ReadFile("../queries/dsr.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(string(raw))
	for _, required := range []string{
		"-- name: getdatasubjectrequestforupdate :one",
		"for update",
		"and status = sqlc.arg(expected_status)",
		"-- name: redactdsrsubjectidentifiers :execrows",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("dsr transactional query contract is missing %q", required)
		}
	}
}
