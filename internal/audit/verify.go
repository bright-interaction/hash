// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

const maxChainFailureDetail = 100

// ChainVerifyResult is shared by the authenticated diagnostic endpoint and
// the release-blocking all-org verifier. Complete is true only after the
// caller has supplied every page from one consistent database snapshot.
type ChainVerifyResult struct {
	OK            bool                `json:"ok"`
	Complete      bool                `json:"complete"`
	TotalChecked  int                 `json:"total_checked"`
	FailureCount  int                 `json:"failure_count"`
	FirstBadIndex int                 `json:"first_bad_index"`
	Failures      []ChainCheckFailure `json:"failures,omitempty"`
}

type ChainCheckFailure struct {
	EventID        string `json:"event_id"`
	Index          int    `json:"index"`
	StoredRowHash  string `json:"stored_row_hash"`
	RecomputedHash string `json:"recomputed_hash"`
	PrevHash       string `json:"prev_hash"`
	Kind           string `json:"kind"`
	Reason         string `json:"reason"`
}

type ChainVerifier struct {
	result ChainVerifyResult
	prev   []byte
}

func NewChainVerifier() *ChainVerifier {
	return &ChainVerifier{result: ChainVerifyResult{
		OK: true, Complete: false, FirstBadIndex: -1,
	}}
}

func (v *ChainVerifier) fail(failure ChainCheckFailure) {
	v.result.OK = false
	v.result.FailureCount++
	if v.result.FirstBadIndex == -1 {
		v.result.FirstBadIndex = failure.Index
	}
	if len(v.result.Failures) < maxChainFailureDetail {
		v.result.Failures = append(v.result.Failures, failure)
	}
}

// VerifyPage consumes the next chronological page. Callers must use keyset
// pagination under one repeatable-read snapshot and must not skip/reorder rows.
func (v *ChainVerifier) VerifyPage(rows []*generated.Event) {
	for _, row := range rows {
		i := v.result.TotalChecked
		v.result.TotalChecked++
		if row == nil {
			v.fail(ChainCheckFailure{Index: i, Reason: "event query returned a nil row"})
			continue
		}
		stored := row.RowHash

		if row.PayloadHashed == nil {
			v.fail(ChainCheckFailure{
				EventID:       row.ID.String(),
				Index:         i,
				StoredRowHash: hex.EncodeToString(stored),
				PrevHash:      hex.EncodeToString(v.prev),
				Kind:          row.Kind,
				Reason:        "legacy row (pre-canonical hashing, no payload_hashed); not verifiable",
			})
			v.prev = stored
			continue
		}

		expected, _ := RecomputeEventRowHash(row)
		linkOK := bytes.Equal(row.PrevHash, v.prev)
		hashOK := len(stored) > 0 && bytes.Equal(stored, expected)
		if !linkOK || !hashOK {
			reason := "row_hash does not match recompute over the bound fields"
			if len(stored) == 0 {
				reason = "row_hash missing"
			} else if !linkOK {
				reason = "stored prev_hash diverges from previous row's row_hash"
			}
			v.fail(ChainCheckFailure{
				EventID:        row.ID.String(),
				Index:          i,
				StoredRowHash:  hex.EncodeToString(stored),
				RecomputedHash: hex.EncodeToString(expected),
				PrevHash:       hex.EncodeToString(v.prev),
				Kind:           row.Kind,
				Reason:         reason,
			})
		}
		v.prev = stored
	}
}

// RecomputeEventRowHash hashes the exact forensic fields persisted on one
// canonical event, including its stored prev_hash. Continuity with the actual
// preceding org event is a separate chain-level check.
func RecomputeEventRowHash(row *generated.Event) ([]byte, error) {
	if row == nil {
		return nil, errors.New("nil event")
	}
	if row.PayloadHashed == nil {
		return nil, errors.New("event has no canonical payload_hashed")
	}
	if !row.CreatedAt.Valid {
		return nil, errors.New("event has no created_at")
	}
	return ChainHashRecord(HashInput{
		Prev:      row.PrevHash,
		OrgID:     row.OrgID,
		DocID:     pgUUIDOrZero(row.DocumentID),
		RecID:     pgUUIDOrZero(row.RecipientID),
		ActorID:   pgUUIDOrZero(row.ActorUserID),
		Kind:      row.Kind,
		IP:        ipString(row.Ip),
		UA:        textString(row.Ua),
		CreatedAt: row.CreatedAt.Time,
		Payload:   row.PayloadHashed,
	}), nil
}

// DocumentEventSetDigest commits to the exact chronological event IDs and
// canonical row hashes present for one document at certificate time. It does
// not claim that a document-only subset proves reachability through the
// interleaved org chain; the separately signed org head is the external anchor.
func DocumentEventSetDigest(rows []*generated.Event) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	h := sha256.New()
	_, _ = h.Write([]byte("hash:document-events:v1\x00"))
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(rows)))
	_, _ = h.Write(count[:])
	var previous *generated.Event
	for i, row := range rows {
		if row == nil {
			return zero, fmt.Errorf("event %d is nil", i)
		}
		if !row.CreatedAt.Valid || len(row.RowHash) != sha256.Size {
			return zero, fmt.Errorf("event %s lacks canonical timestamp or row hash", row.ID)
		}
		if previous != nil {
			if row.CreatedAt.Time.Before(previous.CreatedAt.Time) ||
				(row.CreatedAt.Time.Equal(previous.CreatedAt.Time) && bytes.Compare(row.ID[:], previous.ID[:]) <= 0) {
				return zero, fmt.Errorf("events are not in strict chronological order at index %d", i)
			}
		}
		_, _ = h.Write(row.ID[:])
		_, _ = h.Write(row.RowHash)
		previous = row
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func (v *ChainVerifier) Result() ChainVerifyResult {
	result := v.result
	result.Complete = true
	return result
}

func pgUUIDOrZero(value pgtype.UUID) uuid.UUID {
	if !value.Valid {
		return uuid.Nil
	}
	return uuid.UUID(value.Bytes)
}

func ipString(value *netip.Addr) string {
	if value == nil {
		return ""
	}
	return value.String()
}

func textString(value pgtype.Text) string {
	if !value.Valid {
		return ""
	}
	return value.String
}
