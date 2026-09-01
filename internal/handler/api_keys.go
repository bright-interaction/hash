// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
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
	// API keys also authenticate the core standalone automation endpoint. Key
	// issuance therefore cannot inherit MCP's plan entitlement: /mcp rechecks
	// its own feature gate on every use, while the same credential remains valid
	// for /api/automation/v1/signature-requests when it has both write scopes.
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

	row, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (*generated.ApiKey, error) {
			return q.CreateAPIKey(r.Context(), generated.CreateAPIKeyParams{
				OrgID:     u.OrgID,
				UserID:    u.UserID,
				KeyPrefix: key.Prefix,
				KeyHash:   key.Hash,
				Name:      in.Name,
				Scopes:    scopes,
				ExpiresAt: expires,
			})
		},
		func(created *generated.ApiKey) audit.Entry {
			return audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID,
				Kind: "api_key.created",
				IP:   clientIP(r),
				Payload: map[string]any{
					"key_id":     created.ID,
					"key_prefix": created.KeyPrefix,
					"name":       in.Name,
					"scopes":     scopes,
				},
			}
		},
	)
	if err != nil {
		writeInternalErrorMsg(w, "create api key failed", err)
		return
	}

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
	_, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (uuid.UUID, error) {
			return q.DeleteAPIKey(r.Context(), generated.DeleteAPIKeyParams{ID: id, UserID: u.UserID})
		},
		func(deletedID uuid.UUID) audit.Entry {
			return audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID,
				Kind:    "api_key.revoked",
				IP:      clientIP(r),
				Payload: map[string]any{"key_id": deletedID},
			}
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "api key not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
