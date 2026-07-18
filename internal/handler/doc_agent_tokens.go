// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/db/generated"
)

// v1.1 per-document agent token surface.
//
//   POST   /api/v1/documents/{id}/agent-tokens   mint (returns plaintext once)
//   GET    /api/v1/documents/{id}/agent-tokens   list metadata
//   DELETE /api/v1/agent-tokens/{token_id}       revoke

const (
	maxAgentTokenTTL = 90 * 24 * time.Hour
	defaultTTL       = 7 * 24 * time.Hour
)

type mintAgentTokenInput struct {
	Name     string   `json:"name"`
	TTLHours int      `json:"ttl_hours"` // optional; defaults to 7d, capped at 90d
	MaxUses  int      `json:"max_uses"`  // 0 = unlimited until expiry
	Scopes   []string `json:"scopes"`    // empty defaults to ['read']
}

func (s *Server) handleMintDocAgentToken(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if _, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: sess.OrgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var in mintAgentTokenInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil && err.Error() != "EOF" {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	ttl := time.Duration(in.TTLHours) * time.Hour
	if ttl <= 0 {
		ttl = defaultTTL
	}
	if ttl > maxAgentTokenTTL {
		ttl = maxAgentTokenTTL
	}
	scopes := in.Scopes
	if len(scopes) == 0 {
		// Write-by-default preserves prior behaviour; pass ["read"] for a
		// read-only doc token now that write tools enforce the scope.
		scopes = []string{"read", "write"}
	}
	for _, sc := range scopes {
		switch sc {
		case "read", "write", "sign":
		default:
			writeError(w, http.StatusBadRequest, "scopes must be a subset of [read, write, sign]")
			return
		}
	}
	if in.MaxUses < 0 {
		writeError(w, http.StatusBadRequest, "max_uses must be >= 0")
		return
	}
	minted, err := auth.MintAPIKey()
	if err != nil {
		writeInternalErrorMsg(w, "mint", err)
		return
	}
	row, err := s.Queries.InsertDocAgentToken(r.Context(), generated.InsertDocAgentTokenParams{
		DocumentID: docID,
		OrgID:      sess.OrgID,
		Name:       in.Name,
		Prefix:     minted.Prefix,
		KeyHash:    minted.Hash,
		Scopes:     scopes,
		CreatedBy:  pgtype.UUID{Bytes: sess.UserID, Valid: true},
		ExpiresAt:  pgtype.Timestamptz{Time: time.Now().Add(ttl), Valid: true},
		MaxUses:    int32(in.MaxUses),
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID:       sess.OrgID,
		ActorUserID: &sess.UserID,
		DocumentID:  &docID,
		Kind:        "doc_agent_token.minted",
		IP:          firstIPFromHeader(r),
		UserAgent:   r.UserAgent(),
		Payload: map[string]any{
			"token_id":  row.ID.String(),
			"prefix":    row.Prefix,
			"ttl_hours": int(ttl.Hours()),
			"max_uses":  in.MaxUses,
			"scopes":    scopes,
		},
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         row.ID.String(),
		"prefix":     row.Prefix,
		"name":       row.Name,
		"scopes":     []string(row.Scopes),
		"max_uses":   row.MaxUses,
		"expires_at": row.ExpiresAt.Time.UTC().Format(time.RFC3339),
		"token":      minted.Plaintext, // returned exactly once
	})
}

func (s *Server) handleListDocAgentTokens(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if _, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: sess.OrgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	rows, err := s.Queries.ListDocAgentTokens(r.Context(), generated.ListDocAgentTokensParams{
		DocumentID: docID,
		OrgID:      sess.OrgID,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, t := range rows {
		entry := map[string]any{
			"id":         t.ID.String(),
			"prefix":     t.Prefix,
			"name":       t.Name,
			"scopes":     []string(t.Scopes),
			"max_uses":   t.MaxUses,
			"used_count": t.UsedCount,
			"created_at": t.CreatedAt.Time.UTC().Format(time.RFC3339),
			"expires_at": t.ExpiresAt.Time.UTC().Format(time.RFC3339),
		}
		if t.LastUsedAt.Valid {
			entry["last_used_at"] = t.LastUsedAt.Time.UTC().Format(time.RFC3339)
		}
		if t.RevokedAt.Valid {
			entry["revoked_at"] = t.RevokedAt.Time.UTC().Format(time.RFC3339)
		}
		out = append(out, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out, "count": len(out)})
}

func (s *Server) handleRevokeDocAgentToken(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	row, err := s.Queries.RevokeDocAgentToken(r.Context(), generated.RevokeDocAgentTokenParams{
		ID:    id,
		OrgID: sess.OrgID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "token not found or already revoked")
			return
		}
		writeInternalError(w, err)
		return
	}
	docID := row.DocumentID
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID:       sess.OrgID,
		ActorUserID: &sess.UserID,
		DocumentID:  &docID,
		Kind:        "doc_agent_token.revoked",
		Payload:     map[string]any{"token_id": id.String()},
	})
	w.WriteHeader(http.StatusNoContent)
}
