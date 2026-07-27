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
	row, err := s.Envelopes.PromoteToEnvelope(r.Context(), docID, sess.OrgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found or not eligible (must be draft + blocks-source + not a child)")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: sess.OrgID, ActorUserID: &sess.UserID, DocumentID: &docID,
		Kind:      audit.KindDocumentUpdated,
		IP:        firstIPFromHeader(r),
		UserAgent: r.UserAgent(),
		Payload:   map[string]any{"via": "rest", "tool": "promote_to_envelope"},
	})
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
	row, err := s.Envelopes.Attach(r.Context(), envelopeID, childID, sess.OrgID, in.Position)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: sess.OrgID, ActorUserID: &sess.UserID, DocumentID: &envelopeID,
		Kind:      audit.KindDocumentUpdated,
		IP:        firstIPFromHeader(r),
		UserAgent: r.UserAgent(),
		Payload:   map[string]any{"via": "rest", "tool": "attach_to_envelope", "child_id": childID.String()},
	})
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
	row, err := s.Envelopes.Detach(r.Context(), childID, sess.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: sess.OrgID, ActorUserID: &sess.UserID, DocumentID: &envelopeID,
		Kind:      audit.KindDocumentUpdated,
		IP:        firstIPFromHeader(r),
		UserAgent: r.UserAgent(),
		Payload:   map[string]any{"via": "rest", "tool": "detach_from_envelope", "child_id": childID.String()},
	})
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
	if err := s.Envelopes.Reorder(r.Context(), envelopeID, sess.OrgID, ids); err != nil {
		writeInternalError(w, err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: sess.OrgID, ActorUserID: &sess.UserID, DocumentID: &envelopeID,
		Kind:      audit.KindDocumentUpdated,
		IP:        firstIPFromHeader(r),
		UserAgent: r.UserAgent(),
		Payload:   map[string]any{"via": "rest", "tool": "reorder_envelope", "count": len(ids)},
	})
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
