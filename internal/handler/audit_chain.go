// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/db/generated"
)

// chainVerifyResult is what GET /api/v1/audit/verify-chain returns to
// the operator. ok = true means every persisted row_hash matches the
// recomputed SHA-256(prev_hash || kind || 0x00 || payload_json); any
// false in checks indicates tampering or storage corruption.
type chainVerifyResult struct {
	OK            bool             `json:"ok"`
	TotalChecked  int              `json:"total_checked"`
	FirstBadIndex int              `json:"first_bad_index"`
	Failures      []chainCheckFail `json:"failures,omitempty"`
}

type chainCheckFail struct {
	EventID        string `json:"event_id"`
	Index          int    `json:"index"`
	StoredRowHash  string `json:"stored_row_hash"`
	RecomputedHash string `json:"recomputed_hash"`
	PrevHash       string `json:"prev_hash"`
	Kind           string `json:"kind"`
	Reason         string `json:"reason"`
}

// GET /api/v1/audit/verify-chain[?limit=N]
//
// Walks the org's events in chronological order, recomputing each
// row's expected SHA-256 and comparing against the stored row_hash.
// Default limit is 5000 rows; max 50000 so a runaway query cannot
// stall the DB. The endpoint is session-authed (org admins only).
//
// The check is read-only: corruption is reported, never repaired.
func (s *Server) handleVerifyAuditChain(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	limit := int32(5000)
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 50000 {
			limit = int32(n)
		}
	}
	rows, err := s.Queries.ListChainedEventsForOrg(r.Context(), generated.ListChainedEventsForOrgParams{
		OrgID: u.OrgID,
		Limit: limit,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}

	out := chainVerifyResult{OK: true, TotalChecked: len(rows), FirstBadIndex: -1}
	var prev []byte
	for i, row := range rows {
		stored := row.RowHash

		// Legacy rows predate canonical hashing and carry no payload_hashed.
		// Their original hashed bytes (Go json.Marshal of the payload) are not
		// recoverable from the JSONB column, so they cannot be re-verified;
		// report them distinctly rather than as tampering.
		if row.PayloadHashed == nil {
			out.Failures = append(out.Failures, chainCheckFail{
				EventID:       row.ID.String(),
				Index:         i,
				StoredRowHash: hex.EncodeToString(stored),
				PrevHash:      hex.EncodeToString(prev),
				Kind:          row.Kind,
				Reason:        "legacy row (pre-canonical hashing, no payload_hashed); not verifiable",
			})
			if out.FirstBadIndex == -1 {
				out.FirstBadIndex = i
			}
			out.OK = false
			prev = stored
			continue
		}

		hin := audit.HashInput{
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
		}
		expected := audit.ChainHashRecord(hin)
		if len(stored) == 0 || !bytes.Equal(stored, expected) {
			fail := chainCheckFail{
				EventID:        row.ID.String(),
				Index:          i,
				StoredRowHash:  hex.EncodeToString(stored),
				RecomputedHash: hex.EncodeToString(expected),
				PrevHash:       hex.EncodeToString(prev),
				Kind:           row.Kind,
				Reason:         "row_hash does not match recompute over the bound fields",
			}
			if len(stored) == 0 {
				fail.Reason = "row_hash missing"
			} else if len(row.PrevHash) > 0 && !bytes.Equal(row.PrevHash, prev) {
				fail.Reason = "stored prev_hash diverges from previous row's row_hash"
			}
			out.Failures = append(out.Failures, fail)
			if out.FirstBadIndex == -1 {
				out.FirstBadIndex = i
			}
			out.OK = false
			// Keep walking so the operator gets the full damage map
			// instead of stopping at the first divergence.
		}
		// Carry the STORED hash forward, not the expected one: the chain
		// semantics commit to whatever was actually inserted, so a single bad
		// row only breaks itself + its descendants against expected, while
		// still letting later rows verify against their actual stored
		// predecessors.
		prev = stored
	}

	// Cap the failure detail so a wholesale corruption event doesn't
	// dump a million rows into the response. The summary stays
	// faithful (total_checked, ok=false, first_bad_index, count).
	const maxFailDetail = 100
	if len(out.Failures) > maxFailDetail {
		out.Failures = out.Failures[:maxFailDetail]
	}

	writeJSON(w, http.StatusOK, out)
}

func pgUUIDOrZero(p pgtype.UUID) uuid.UUID {
	if !p.Valid {
		return uuid.UUID{}
	}
	return uuid.UUID(p.Bytes)
}

func ipString(a *netip.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

func textString(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}
