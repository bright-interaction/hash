// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/envelopes"
)

// Phase 8.6 envelope REST surface. Envelopes ARE documents (with
// is_envelope=true), so the existing /documents endpoints handle GET /
// PATCH / DELETE; these handlers add the envelope-specific ops.

// POST /api/v1/documents/{id}/promote-to-envelope
func (s *Server) handlePromoteToEnvelope(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if s.Envelopes == nil {
		writeError(w, http.StatusServiceUnavailable, "envelopes engine not configured")
		return
	}
	row, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (*generated.Document, error) {
			return envelopes.New(q).PromoteToEnvelope(r.Context(), docID, sess.OrgID)
		},
		func(*generated.Document) audit.Entry {
			return audit.Entry{
				OrgID: sess.OrgID, ActorUserID: &sess.UserID, DocumentID: &docID,
				Kind:      audit.KindDocumentUpdated,
				IP:        firstIPFromHeader(r),
				UserAgent: r.UserAgent(),
				Payload:   map[string]any{"via": "rest", "tool": "promote_to_envelope"},
			}
		},
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found or not eligible (must be draft + blocks-source + not a child)")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(row))
}

// POST /api/v1/envelopes/{id}/attach
//
// Body: { "child_id": "<uuid>", "position": <int, optional> }
func (s *Server) handleAttachToEnvelope(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	envelopeID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		ChildID  string `json:"child_id"`
		Position int32  `json:"position"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	childID, err := uuid.Parse(in.ChildID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "child_id must be a uuid")
		return
	}
	row, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (*generated.Document, error) {
			return envelopes.New(q).Attach(r.Context(), envelopeID, childID, sess.OrgID, in.Position)
		},
		func(*generated.Document) audit.Entry {
			return audit.Entry{
				OrgID: sess.OrgID, ActorUserID: &sess.UserID, DocumentID: &envelopeID,
				Kind:      audit.KindDocumentUpdated,
				IP:        firstIPFromHeader(r),
				UserAgent: r.UserAgent(),
				Payload:   map[string]any{"via": "rest", "tool": "attach_to_envelope", "child_id": childID.String()},
			}
		},
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(row))
}

// POST /api/v1/envelopes/{id}/detach
//
// Body: { "child_id": "<uuid>" }
func (s *Server) handleDetachFromEnvelope(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	envelopeID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		ChildID string `json:"child_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	childID, err := uuid.Parse(in.ChildID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "child_id must be a uuid")
		return
	}
	row, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (*generated.Document, error) {
			return envelopes.New(q).Detach(r.Context(), childID, sess.OrgID)
		},
		func(*generated.Document) audit.Entry {
			return audit.Entry{
				OrgID: sess.OrgID, ActorUserID: &sess.UserID, DocumentID: &envelopeID,
				Kind:      audit.KindDocumentUpdated,
				IP:        firstIPFromHeader(r),
				UserAgent: r.UserAgent(),
				Payload:   map[string]any{"via": "rest", "tool": "detach_from_envelope", "child_id": childID.String()},
			}
		},
	)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(row))
}

// POST /api/v1/envelopes/{id}/reorder
//
// Body: { "child_ids": ["<uuid>", "<uuid>", ...] }
func (s *Server) handleReorderEnvelope(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	envelopeID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		ChildIDs []string `json:"child_ids"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	ids := make([]uuid.UUID, 0, len(in.ChildIDs))
	for _, raw := range in.ChildIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "child_ids must be uuids")
			return
		}
		ids = append(ids, id)
	}
	if _, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: envelopeID, OrgID: sess.OrgID}); err != nil {
		writeError(w, http.StatusNotFound, "envelope not found")
		return
	}
	if s.Audit == nil {
		writeInternalErrorMsg(w, "reorder envelope", errors.New("audit unavailable"))
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := envelopes.New(s.Queries.WithTx(tx)).Reorder(r.Context(), envelopeID, sess.OrgID, ids); err != nil {
		writeInternalError(w, err)
		return
	}
	pending, err := s.Audit.LogTx(r.Context(), tx, audit.Entry{
		OrgID: sess.OrgID, ActorUserID: &sess.UserID, DocumentID: &envelopeID,
		Kind:      audit.KindDocumentUpdated,
		IP:        firstIPFromHeader(r),
		UserAgent: r.UserAgent(),
		Payload:   map[string]any{"via": "rest", "tool": "reorder_envelope", "count": len(ids)},
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeInternalError(w, err)
		return
	}
	s.Audit.Publish(pending)
	children, err := s.Envelopes.Children(r.Context(), envelopeID, sess.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]any, 0, len(children))
	for _, c := range children {
		out = append(out, toDocumentResponse(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"children": out, "count": len(out)})
}

// GET /api/v1/envelopes/{id}/children
func (s *Server) handleListEnvelopeChildren(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	envelopeID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	children, err := s.Envelopes.Children(r.Context(), envelopeID, sess.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]any, 0, len(children))
	for _, c := range children {
		out = append(out, toDocumentResponse(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"children": out, "count": len(out)})
}

// GET /api/v1/envelopes/{id}/manifest
//
// Returns the audit-cert manifest as JSON. The same shape is rendered
// inside the cert HTML for an envelope's PDFs.
func (s *Server) handleEnvelopeManifest(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	envelopeID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	env, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: envelopeID, OrgID: sess.OrgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "envelope not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	if !env.IsEnvelope {
		writeError(w, http.StatusBadRequest, "document is not an envelope")
		return
	}
	manifest, err := s.Envelopes.BuildManifest(r.Context(), env)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, manifest)
}
