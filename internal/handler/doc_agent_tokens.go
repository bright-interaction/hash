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

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// v1.1 per-document agent token surface.
//
//   POST   /api/v1/documents/{id}/agent-tokens   mint (returns plaintext once)
//   GET    /api/v1/documents/{id}/agent-tokens   list metadata
//   DELETE /api/v1/agent-tokens/{token_id}       revoke

const (
	maxAgentTokenTTL     = 90 * 24 * time.Hour
	maxAgentTokenTTLDays = 90
	maxAgentTokenUses    = int64(1<<31 - 1)
	defaultTTL           = 7 * 24 * time.Hour
)

type mintAgentTokenInput struct {
	Name    string   `json:"name"`
	TTLDays int      `json:"ttl_days"` // optional; defaults to 7d, capped at 90d
	MaxUses int64    `json:"max_uses"` // 0 = unlimited until expiry
	Scopes  []string `json:"scopes"`   // empty defaults to ['read']
}

func normalizeDocAgentScopes(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return []string{"read"}, nil
	}
	scopes := append([]string(nil), requested...)
	for _, scope := range scopes {
		switch scope {
		case "read", "write:authoring", "write:workflow":
		default:
			return nil, errors.New("scopes must be a subset of [read, write:authoring, write:workflow]")
		}
	}
	return scopes, nil
}

func docAgentTokenTTL(days int) time.Duration {
	if days <= 0 {
		return defaultTTL
	}
	if days > maxAgentTokenTTLDays {
		return maxAgentTokenTTL
	}
	return time.Duration(days) * 24 * time.Hour
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
	ttl := docAgentTokenTTL(in.TTLDays)
	scopes, err := normalizeDocAgentScopes(in.Scopes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.MaxUses < 0 || in.MaxUses > maxAgentTokenUses {
		writeError(w, http.StatusBadRequest, "max_uses must be between 0 and 2147483647")
		return
	}
	minted, err := auth.MintDocumentAgentKey()
	if err != nil {
		writeInternalErrorMsg(w, "mint", err)
		return
	}
	row, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (*generated.DocumentAgentToken, error) {
			return q.InsertDocAgentToken(r.Context(), generated.InsertDocAgentTokenParams{
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
		},
		func(created *generated.DocumentAgentToken) audit.Entry {
			return audit.Entry{
				OrgID:       sess.OrgID,
				ActorUserID: &sess.UserID,
				DocumentID:  &docID,
				Kind:        "doc_agent_token.minted",
				IP:          firstIPFromHeader(r),
				UserAgent:   r.UserAgent(),
				Payload: map[string]any{
					"token_id": created.ID.String(),
					"prefix":   created.Prefix,
					"ttl_days": int(ttl.Hours() / 24),
					"max_uses": in.MaxUses,
					"scopes":   scopes,
				},
			}
		},
	)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         row.ID.String(),
		"prefix":     row.Prefix,
		"name":       row.Name,
		"scopes":     []string(row.Scopes),
		"max_uses":   row.MaxUses,
		"used_count": row.UsedCount,
		"created_at": row.CreatedAt.Time.UTC().Format(time.RFC3339),
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
	_, err = audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (*generated.DocumentAgentToken, error) {
			return q.RevokeDocAgentToken(r.Context(), generated.RevokeDocAgentTokenParams{
				ID: id, OrgID: sess.OrgID,
			})
		},
		func(revoked *generated.DocumentAgentToken) audit.Entry {
			docID := revoked.DocumentID
			return audit.Entry{
				OrgID:       sess.OrgID,
				ActorUserID: &sess.UserID,
				DocumentID:  &docID,
				Kind:        "doc_agent_token.revoked",
				Payload:     map[string]any{"token_id": revoked.ID.String()},
			}
		},
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "token not found or already revoked")
			return
		}
		writeInternalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
