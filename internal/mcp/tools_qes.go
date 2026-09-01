// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
)

var (
	errQESRecordNotArchival = errors.New("QES ceremony lifecycle is unavailable; only completed historical records may be inspected")
	errQESRecordIncomplete  = errors.New("historical QES record is incomplete and cannot be represented safely")
)

const historicalQESWarning = "Unverified legacy material only: Hash does not validate this record as a Qualified Electronic Signature, bind it to the document digest, or assert legal effect."

// registerQESTools deliberately exposes no ceremony start, callback, resume, or
// polling operation. The sole compatibility tool is a read-only, tenant- and
// document-scoped archive reader for completed records created by pre-release
// builds. It labels the raw provider material as unverified instead of turning
// a legacy database row into a new QES claim.
func registerQESTools(s *Server, d Deps) {
	s.RegisterTool(ToolDef{
		Name:        "get_qes_session",
		Description: "Read a completed historical QES session record created by a pre-release build. Archival only: this tool cannot start, poll, resume, or advance a ceremony, and returned provider material is unverified and must not be treated as proof of a valid QES or legal effect.",
		InputSchema: schemaObject(map[string]any{
			"session_id": stringSchema("historical qes_signing_sessions uuid"),
		}, []string{"session_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				SessionID string `json:"session_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.SessionID)
			if err != nil {
				return nil, errors.New("session_id must be a uuid")
			}
			row, err := d.Queries.GetQESSession(r.Context(), id)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("historical QES record not found")
			}
			if err != nil {
				return nil, err
			}
			if row.OrgID != u.OrgID {
				return nil, errors.New("historical QES record does not belong to this org")
			}
			if err := auth.EnforceDocScope(r.Context(), row.DocumentID); err != nil {
				return nil, err
			}
			return historicalQESRecord(row)
		},
	})
}

func historicalQESRecord(row *generated.QesSigningSession) (map[string]any, error) {
	if row == nil || row.Status != "completed" || !row.CompletedAt.Valid {
		return nil, errQESRecordNotArchival
	}
	if len(row.IdentityAssertionJson) == 0 || !json.Valid(row.IdentityAssertionJson) ||
		!row.SignatureB64.Valid || strings.TrimSpace(row.SignatureB64.String) == "" {
		return nil, errQESRecordIncomplete
	}
	out := map[string]any{
		"record_classification": "unverified_legacy_qes_material",
		"warning":               historicalQESWarning,
		"session_id":            row.ID.String(),
		"document_id":           row.DocumentID.String(),
		"recipient_id":          row.RecipientID.String(),
		"provider":              row.Provider,
		"status":                row.Status,
		"created_at":            row.CreatedAt.Time.UTC(),
		"completed_at":          row.CompletedAt.Time.UTC(),
		"identity_assertion":    json.RawMessage(row.IdentityAssertionJson),
		"signature_b64":         row.SignatureB64.String,
	}
	if row.ExpiresAt.Valid {
		out["expires_at"] = row.ExpiresAt.Time.UTC()
	}
	if row.CertChainPem.Valid && strings.TrimSpace(row.CertChainPem.String) != "" {
		out["cert_chain_pem"] = row.CertChainPem.String
	}
	return out, nil
}
