// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/qes"
)

// registerQESTools mounts v1.1 Qualified Electronic Signature MCP
// tools so agents can:
//   - start a QES session for a recipient on a QES-tier document
//   - poll the session status
//   - inspect the persisted identity assertion + signature after
//     completion (for audit / compliance reports)
//
// These tools are intentionally NOT authoring surfaces; an agent can't
// adopt-and-sign as a QES signer because that would defeat the
// authentication purpose. The mutations they DO expose (start, status,
// inspect) match what a customer-success bot would need to walk a
// signer through a stuck flow.
func registerQESTools(s *Server, d Deps) {
	if d.QES == nil {
		return
	}

	s.RegisterTool(ToolDef{
		Name:        "start_qes_session",
		Write:       true,
		MinFeature:  "qes", // paid-feature gate, mirroring the REST handleQESStart
		Description: "Start a Qualified Electronic Signature challenge for a recipient on a QES-tier document. Returns the QTSP redirect URL the signer's browser should navigate to. Errors when the document is not QES-tier (use set_document_routing_tier first) or when QES is not configured on this instance.",
		InputSchema: schemaObject(map[string]any{
			"document_id":  stringSchema("document uuid"),
			"recipient_id": stringSchema("recipient uuid"),
		}, []string{"document_id", "recipient_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID  string `json:"document_id"`
				RecipientID string `json:"recipient_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			docID, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), docID); err != nil {
				return nil, err
			}
			recID, err := uuid.Parse(p.RecipientID)
			if err != nil {
				return nil, errors.New("recipient_id must be a uuid")
			}
			doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			if !strings.EqualFold(doc.RoutingTier, "QES") {
				return nil, errors.New("document routing_tier is not QES; call set_document_routing_tier first")
			}
			rec, err := d.Queries.GetRecipient(r.Context(), generated.GetRecipientParams{ID: recID, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("recipient not found")
			}
			if err != nil {
				return nil, err
			}
			if rec.DocumentID != docID {
				return nil, errors.New("recipient does not belong to that document")
			}
			// Hash a stable representation of the document so the QTSP
			// signs over a known digest. The agent flow can't reach the
			// fully-rendered HTML the way the signer page does, so we
			// hash blocks_json which IS the canonical authored content.
			digest := sha256.Sum256(doc.BlocksJson)
			session, err := d.QES.StartSession(r.Context(), qes.StartInput{
				DocumentID:     doc.ID,
				RecipientID:    rec.ID,
				RecipientEmail: rec.Email,
				RecipientName:  rec.Name,
				CallbackURL:    strings.TrimRight(d.PublicURL, "/") + "/qes/callback/__session__",
				SignedDigest:   digest,
			}, u.OrgID)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"session_id":   session.ID.String(),
				"provider":     session.Provider,
				"redirect_url": strings.ReplaceAll(session.RedirectURL, "__session__", session.ProviderSessionID),
				"status":       session.Status,
				"expires_at":   session.ExpiresAt.UTC(),
			}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "get_qes_session",
		Description: "Return the current state of a QES signing session: pending | redirected | completed | failed | expired. Includes the persisted identity assertion + signature (base64) + cert chain (PEM) when status=completed, for audit / compliance reports.",
		InputSchema: schemaObject(map[string]any{
			"session_id": stringSchema("qes_signing_sessions uuid"),
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
				return nil, errors.New("session not found")
			}
			if err != nil {
				return nil, err
			}
			if row.OrgID != u.OrgID {
				return nil, errors.New("session does not belong to this org")
			}
			// Doc-scoped tokens may only inspect sessions on their bound doc.
			if err := auth.EnforceDocScope(r.Context(), row.DocumentID); err != nil {
				return nil, err
			}
			out := map[string]any{
				"session_id":          row.ID.String(),
				"document_id":         row.DocumentID.String(),
				"recipient_id":        row.RecipientID.String(),
				"provider":            row.Provider,
				"provider_session_id": row.ProviderSessionID,
				"status":              row.Status,
				"created_at":          row.CreatedAt.Time.UTC(),
				"expires_at":          row.ExpiresAt.Time.UTC(),
			}
			if row.CompletedAt.Valid {
				out["completed_at"] = row.CompletedAt.Time.UTC()
			}
			if row.SignatureB64.Valid {
				out["signature_b64"] = row.SignatureB64.String
			}
			if row.CertChainPem.Valid {
				out["cert_chain_pem"] = row.CertChainPem.String
			}
			if len(row.IdentityAssertionJson) > 0 {
				out["identity_assertion"] = json.RawMessage(row.IdentityAssertionJson)
			}
			if row.FailureReason.Valid {
				out["failure_reason"] = row.FailureReason.String
			}
			return out, nil
		},
	})
}
