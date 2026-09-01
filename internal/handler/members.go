// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// Org member management + RBAC role assignment. Roles are owner > sender >
// viewer (see internal/auth/rbac.go). Listing is open to any org member; role
// changes are gated to owners by the route middleware.

type memberResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	IsSelf    bool   `json:"is_self"`
	CreatedAt string `json:"created_at"`
}

func toMemberResponse(u *generated.User, selfID uuid.UUID) memberResponse {
	return memberResponse{
		ID:        u.ID.String(),
		Email:     u.Email,
		Name:      u.Name,
		Role:      u.Role,
		IsSelf:    u.ID == selfID,
		CreatedAt: u.CreatedAt.Time.Format(time.RFC3339),
	}
}

// GET /api/v1/members
func (s *Server) handleListMembers(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	rows, err := s.Queries.ListUsersByOrg(r.Context(), u.OrgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list members failed")
		return
	}
	out := make([]memberResponse, 0, len(rows))
	for _, m := range rows {
		out = append(out, toMemberResponse(m, u.UserID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": out, "count": len(out)})
}

type updateMemberRoleInput struct {
	Role string `json:"role"`
}

func validRole(role string) bool {
	switch role {
	case "owner", "sender", "viewer":
		return true
	}
	return false
}

// PATCH /api/v1/members/{id}/role  (owner-only; gated by route middleware)
func (s *Server) handleUpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in updateMemberRoleInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !validRole(in.Role) {
		writeError(w, http.StatusBadRequest, "role must be owner, sender, or viewer")
		return
	}

	// Serialize role changes for the whole organization. Locking only the target
	// user permits two concurrent last-owner demotions to both observe two owners
	// and leave the tenant ownerless.
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "begin role update failed")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	var lockedOrg uuid.UUID
	if err := tx.QueryRow(r.Context(), `SELECT id FROM orgs WHERE id = $1 FOR UPDATE`, u.OrgID).Scan(&lockedOrg); err != nil {
		writeError(w, http.StatusInternalServerError, "lock organization failed")
		return
	}
	q := s.Queries.WithTx(tx)

	// Resolve the target within the caller's org (ListUsersByOrg is org-scoped,
	// so this also enforces no cross-tenant edits).
	rows, err := q.ListUsersByOrg(r.Context(), u.OrgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	var target *generated.User
	for _, m := range rows {
		if m.ID == id {
			target = m
			break
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "member not found")
		return
	}

	// Never strip the org's last owner: that would lock everyone out of org
	// settings + member management permanently.
	if target.Role == "owner" && in.Role != "owner" {
		owners, oerr := q.CountOrgOwners(r.Context(), u.OrgID)
		if oerr != nil {
			writeError(w, http.StatusInternalServerError, "owner check failed")
			return
		}
		if owners <= 1 {
			writeError(w, http.StatusBadRequest, "cannot demote the last owner; promote another member to owner first")
			return
		}
	}

	row, err := q.UpdateUserRole(r.Context(), generated.UpdateUserRoleParams{
		ID: id, OrgID: u.OrgID, Role: in.Role,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "member not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update role failed")
		return
	}
	pending, err := s.Audit.LogTx(r.Context(), tx, audit.Entry{
		OrgID: u.OrgID, ActorUserID: &u.UserID,
		Kind: "member.role_changed",
		IP:   clientIP(r),
		Payload: map[string]any{
			"member_id": id.String(),
			"from":      target.Role,
			"to":        in.Role,
		},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit role update failed")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "commit role update failed")
		return
	}
	s.Audit.Publish(pending)
	writeJSON(w, http.StatusOK, toMemberResponse(row, u.UserID))
}
