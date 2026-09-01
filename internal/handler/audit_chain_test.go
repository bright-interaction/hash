// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
)

var testOrg = uuid.MustParse("00000000-0000-0000-0000-000000000001")
var testCreatedAt = time.Unix(1_700_000_000, 0).UTC()

func verifyChainRows(rows []*generated.Event) chainVerifyResult {
	v := audit.NewChainVerifier()
	v.VerifyPage(rows)
	return v.Result()
}

func mkChainRow(prev []byte, kind string, payload []byte) *generated.Event {
	rowHash := audit.ChainHashRecord(audit.HashInput{
		Prev:      prev,
		OrgID:     testOrg,
		Kind:      kind,
		CreatedAt: testCreatedAt,
		Payload:   payload,
	})
	return &generated.Event{
		ID:            uuid.New(),
		OrgID:         testOrg,
		Kind:          kind,
		PayloadJson:   payload,
		PayloadHashed: payload,
		PrevHash:      prev,
		RowHash:       rowHash,
		CreatedAt:     pgtype.Timestamptz{Time: testCreatedAt, Valid: true},
	}
}

func TestVerifyChain_HappyPath(t *testing.T) {
	r1 := mkChainRow(nil, "document.created", []byte(`{"id":1}`))
	r2 := mkChainRow(r1.RowHash, "document.sent", []byte(`{"id":1,"recipients":2}`))
	r3 := mkChainRow(r2.RowHash, "document.signed", []byte(`{"signer":"a"}`))
	got := verifyChainRows([]*generated.Event{r1, r2, r3})
	if !got.OK || got.FirstBadIndex != -1 {
		t.Errorf("happy chain should verify; got %+v", got)
	}
	if got.TotalChecked != 3 {
		t.Errorf("expected 3 rows checked, got %d", got.TotalChecked)
	}
}

func TestVerifyChain_TamperedPayload(t *testing.T) {
	r1 := mkChainRow(nil, "document.created", []byte(`{"id":1}`))
	r2 := mkChainRow(r1.RowHash, "document.sent", []byte(`{"id":1}`))
	// Tamper r2's hashed payload AFTER its row_hash was computed.
	r2.PayloadHashed = []byte(`{"id":99,"tampered":true}`)
	got := verifyChainRows([]*generated.Event{r1, r2})
	if got.OK {
		t.Error("tampered payload should fail verification")
	}
	if got.FirstBadIndex != 1 {
		t.Errorf("expected first divergence at index 1, got %d", got.FirstBadIndex)
	}
}

func TestVerifyChain_TamperedForensicColumn(t *testing.T) {
	r1 := mkChainRow(nil, "document.created", []byte(`{"id":1}`))
	// Editing a forensic column (ip) after the fact must break the hash: the
	// row was hashed with no IP, so attaching one diverges from the recompute.
	addr := netip.MustParseAddr("9.9.9.9")
	r1.Ip = &addr
	got := verifyChainRows([]*generated.Event{r1})
	if got.OK {
		t.Error("tampered ip column should fail verification")
	}
}

func TestVerifyChain_LegacyRowFlagged(t *testing.T) {
	// A pre-canonical row has no payload_hashed: not verifiable, flagged.
	row := &generated.Event{
		ID:          uuid.New(),
		OrgID:       testOrg,
		Kind:        "document.legacy",
		PayloadJson: []byte(`{}`),
		// PayloadHashed nil
	}
	got := verifyChainRows([]*generated.Event{row})
	if got.OK {
		t.Error("legacy row (no payload_hashed) should be flagged")
	}
}

func TestVerifyChain_EmptyChainIsOK(t *testing.T) {
	got := verifyChainRows(nil)
	if !got.OK {
		t.Errorf("empty chain should verify trivially; got %+v", got)
	}
	if got.TotalChecked != 0 {
		t.Errorf("expected 0 rows, got %d", got.TotalChecked)
	}
}

func TestVerifyChain_PaginatesWithoutResettingPredecessor(t *testing.T) {
	r1 := mkChainRow(nil, "document.created", []byte(`{"id":1}`))
	r2 := mkChainRow(r1.RowHash, "document.sent", []byte(`{"id":1}`))
	r3 := mkChainRow(r2.RowHash, "document.signed", []byte(`{"id":1}`))
	v := audit.NewChainVerifier()
	v.VerifyPage([]*generated.Event{r1})
	v.VerifyPage([]*generated.Event{r2, r3})
	got := v.Result()
	if !got.OK || !got.Complete || got.TotalChecked != 3 {
		t.Fatalf("paginated chain verification = %+v", got)
	}
}

func TestVerifyChain_CapsDetailsButCountsAllFailures(t *testing.T) {
	rows := make([]*generated.Event, 103)
	for i := range rows {
		rows[i] = &generated.Event{
			ID: uuid.New(), OrgID: testOrg, Kind: "legacy", RowHash: []byte{byte(i)},
		}
	}
	got := verifyChainRows(rows)
	if got.OK || !got.Complete {
		t.Fatalf("corrupt chain should be a complete failed verification: %+v", got)
	}
	if got.FailureCount != len(rows) || len(got.Failures) != 100 {
		t.Fatalf("failure summary/detail = %d/%d, want %d/100", got.FailureCount, len(got.Failures), len(rows))
	}
}

func TestVerifyChain_DetectsPrevHashFieldMutation(t *testing.T) {
	r1 := mkChainRow(nil, "document.created", []byte(`{"id":1}`))
	r2 := mkChainRow(r1.RowHash, "document.sent", []byte(`{"id":1}`))
	// Recompute row_hash against the malicious prev_hash. A verifier that only
	// checks each row in isolation would accept this fork; continuity must fail.
	r2.PrevHash = make([]byte, 32)
	r2.RowHash = audit.ChainHashRecord(audit.HashInput{
		Prev: r2.PrevHash, OrgID: r2.OrgID, Kind: r2.Kind,
		CreatedAt: r2.CreatedAt.Time, Payload: r2.PayloadHashed,
	})
	got := verifyChainRows([]*generated.Event{r1, r2})
	if got.OK || got.FirstBadIndex != 1 || got.Failures[0].Reason != "stored prev_hash diverges from previous row's row_hash" {
		t.Fatalf("forked prev_hash was not detected: %+v", got)
	}
}
