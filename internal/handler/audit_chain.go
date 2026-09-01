// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// chainVerifyResult is what GET /api/v1/audit/verify-chain returns to
// the operator. ok = true means every persisted row_hash matches the
// recomputed SHA-256(prev_hash || kind || 0x00 || payload_json); any
// false in checks indicates tampering or storage corruption.
type chainVerifyResult = audit.ChainVerifyResult

// GET /api/v1/audit/verify-chain[?limit=N]
//
// Walks the org's complete event ledger in chronological order, recomputing
// each expected SHA-256 and comparing it with the stored row_hash. The optional
// limit controls page size only (default 5000, max 50000); it never truncates
// verification. A repeatable-read transaction gives every page one finite,
// consistent snapshot while keeping process memory bounded.
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
	if s.Pool == nil {
		writeInternalError(w, pgx.ErrTxClosed)
		return
	}
	tx, err := s.Pool.BeginTx(r.Context(), pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	q := s.Queries.WithTx(tx)

	pageParams := generated.ListChainedEventsPageForOrgParams{
		OrgID:     u.OrgID,
		PageLimit: limit,
	}
	rows, err := q.ListChainedEventsPageForOrg(r.Context(), pageParams)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	verifier := audit.NewChainVerifier()
	for {
		verifier.VerifyPage(rows)
		if len(rows) < int(limit) {
			break
		}
		last := rows[len(rows)-1]
		pageParams.AfterCreatedAt = last.CreatedAt
		pageParams.AfterID = pgtype.UUID{Bytes: last.ID, Valid: true}
		rows, err = q.ListChainedEventsPageForOrg(r.Context(), pageParams)
		if err != nil {
			writeInternalError(w, err)
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeInternalError(w, err)
		return
	}
	out := verifier.Result()
	writeJSON(w, http.StatusOK, out)
}
