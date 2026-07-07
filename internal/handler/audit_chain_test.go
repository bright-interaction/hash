package handler

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/db/generated"
)

var testOrg = uuid.MustParse("00000000-0000-0000-0000-000000000001")
var testCreatedAt = time.Unix(1_700_000_000, 0).UTC()

// verifyChainRows mirrors the in-handler walk so tests can run the verifier
// without a Postgres connection. If it diverges from handleVerifyAuditChain we
// have a bug.
func verifyChainRows(rows []*generated.ListChainedEventsForOrgRow) chainVerifyResult {
	out := chainVerifyResult{OK: true, TotalChecked: len(rows), FirstBadIndex: -1}
	var prev []byte
	for i, row := range rows {
		stored := row.RowHash
		if row.PayloadHashed == nil {
			out.OK = false
			if out.FirstBadIndex == -1 {
				out.FirstBadIndex = i
			}
			prev = stored
			continue
		}
		expected := audit.ChainHashRecord(audit.HashInput{
			Prev:      prev,
			OrgID:     row.OrgID,
			DocID:     pgUUIDOrZero(row.DocumentID),
			RecID:     pgUUIDOrZero(row.RecipientID),
			ActorID:   pgUUIDOrZero(row.ActorUserID),
			Kind:      row.Kind,
			IP:        ipString(row.Ip),
			UA:        textString(row.Ua),
			CreatedAt: row.CreatedAt.Time,
			Payload:   row.PayloadHashed,
		})
		if len(stored) == 0 || !bytesEqual(stored, expected) {
			out.OK = false
			if out.FirstBadIndex == -1 {
				out.FirstBadIndex = i
			}
		}
		prev = stored
	}
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mkChainRow(prev []byte, kind string, payload []byte) *generated.ListChainedEventsForOrgRow {
	rowHash := audit.ChainHashRecord(audit.HashInput{
		Prev:      prev,
		OrgID:     testOrg,
		Kind:      kind,
		CreatedAt: testCreatedAt,
		Payload:   payload,
	})
	return &generated.ListChainedEventsForOrgRow{
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
	got := verifyChainRows([]*generated.ListChainedEventsForOrgRow{r1, r2, r3})
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
	got := verifyChainRows([]*generated.ListChainedEventsForOrgRow{r1, r2})
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
	got := verifyChainRows([]*generated.ListChainedEventsForOrgRow{r1})
	if got.OK {
		t.Error("tampered ip column should fail verification")
	}
}

func TestVerifyChain_LegacyRowFlagged(t *testing.T) {
	// A pre-canonical row has no payload_hashed: not verifiable, flagged.
	row := &generated.ListChainedEventsForOrgRow{
		ID:          uuid.New(),
		OrgID:       testOrg,
		Kind:        "document.legacy",
		PayloadJson: []byte(`{}`),
		// PayloadHashed nil
	}
	got := verifyChainRows([]*generated.ListChainedEventsForOrgRow{row})
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
