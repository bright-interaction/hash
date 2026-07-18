// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/db/generated"
)

type apiKeyResponse struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	Prefix     string    `json:"key_prefix"`
	Scopes     []string  `json:"scopes"`
	ExpiresAt  string    `json:"expires_at,omitempty"`
	LastUsedAt string    `json:"last_used_at,omitempty"`
	CreatedAt  string    `json:"created_at"`
	// Plaintext is only set on the response from POST /api-keys.
	// Subsequent GETs never return it.
	Plaintext string `json:"plaintext,omitempty"`
}

type listAPIKeysRow struct {
	ID         uuid.UUID
	Name       string
	KeyPrefix  string
	Scopes     []string
	ExpiresAt  pgtype.Timestamptz
	LastUsedAt pgtype.Timestamptz
	CreatedAt  pgtype.Timestamptz
}

func toAPIKeyResponse(r *generated.ListAPIKeysByUserRow) apiKeyResponse {
	out := apiKeyResponse{
		ID:        r.ID,
		Name:      r.Name,
		Prefix:    r.KeyPrefix,
		Scopes:    append([]string{}, r.Scopes...),
		CreatedAt: r.CreatedAt.Time.Format(time.RFC3339),
	}
	if r.ExpiresAt.Valid {
		out.ExpiresAt = r.ExpiresAt.Time.Format(time.RFC3339)
	}
	if r.LastUsedAt.Valid {
		out.LastUsedAt = r.LastUsedAt.Time.Format(time.RFC3339)
	}
	return out
}

type createAPIKeyInput struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expires_at,omitempty"`
}

// handleCreateAPIKey mints a fresh `mth_<prefix>_<secret>` key, hashes it,
// stores the hash, and returns the plaintext exactly once. Caller is
// responsible for displaying + copying the plaintext immediately; it can
// never be retrieved again.
func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	var in createAPIKeyInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	scopes := in.Scopes
	if len(scopes) == 0 {
		// Default to full write-by-default to preserve prior behaviour; a
		// read-only key is now an explicit opt-in (pass scopes: ["read"]).
		scopes = []string{"read", "write:authoring", "write:workflow"}
	}
	for _, sc := range scopes {
		switch sc {
		case "read", "write:authoring", "write:workflow":
		default:
			writeError(w, http.StatusBadRequest, "invalid scope: "+sc)
			return
		}
	}
	var expires pgtype.Timestamptz
	if in.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, in.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "expires_at must be RFC3339")
			return
		}
		expires = pgtype.Timestamptz{Time: t, Valid: true}
	}

	key, err := auth.MintAPIKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key mint failed")
		return
	}

	row, err := s.Queries.CreateAPIKey(r.Context(), generated.CreateAPIKeyParams{
		OrgID:     u.OrgID,
		UserID:    u.UserID,
		KeyPrefix: key.Prefix,
		KeyHash:   key.Hash,
		Name:      in.Name,
		Scopes:    scopes,
		ExpiresAt: expires,
	})
	if err != nil {
		writeInternalErrorMsg(w, "create api key failed", err)
		return
	}

	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: u.OrgID, ActorUserID: &u.UserID,
		Kind: "api_key.created",
		IP:   clientIP(r),
		Payload: map[string]any{
			"key_id":     row.ID,
			"key_prefix": row.KeyPrefix,
			"name":       in.Name,
			"scopes":     scopes,
		},
	})

	out := apiKeyResponse{
		ID:        row.ID,
		Name:      row.Name,
		Prefix:    row.KeyPrefix,
		Scopes:    append([]string{}, row.Scopes...),
		CreatedAt: row.CreatedAt.Time.Format(time.RFC3339),
		Plaintext: key.Plaintext,
	}
	if row.ExpiresAt.Valid {
		out.ExpiresAt = row.ExpiresAt.Time.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	rows, err := s.Queries.ListAPIKeysByUser(r.Context(), u.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list keys failed")
		return
	}
	out := make([]apiKeyResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, toAPIKeyResponse(row))
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_keys": out})
}

func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if err := s.Queries.DeleteAPIKey(r.Context(), generated.DeleteAPIKeyParams{
		ID: id, UserID: u.UserID,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: u.OrgID, ActorUserID: &u.UserID,
		Kind:    "api_key.revoked",
		IP:      clientIP(r),
		Payload: map[string]any{"key_id": id},
	})
	w.WriteHeader(http.StatusNoContent)
}

// guard against unused imports if the file evolves.
var (
	_ = hex.EncodeToString
	_ = errors.New
)
