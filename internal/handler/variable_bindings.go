// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/resolver"
)

// resolveVariables is the single render-time path: every preview, signer
// view, and final-PDF render goes through here so resolution rules stay in
// one place. When the document is non-draft (sent / in_progress / completed
// / etc), we run in FreezeMode so live binding fetches never alter what a
// signed document renders.
func (s *Server) resolveVariables(ctx context.Context, doc *generated.Document) (map[string]string, []resolver.ResolveReport, error) {
	if s.Resolver == nil {
		// fall back to the static-only behaviour from week 2
		out := map[string]string{}
		if len(doc.VariablesJson) > 0 {
			var raw map[string]any
			if err := json.Unmarshal(doc.VariablesJson, &raw); err == nil {
				for k, v := range raw {
					if str, ok := v.(string); ok {
						out[k] = str
					}
				}
			}
		}
		return out, nil, nil
	}
	opts := resolver.ResolveOptions{}
	if doc.Status != "draft" {
		opts.FreezeMode = true
	}
	return s.Resolver.Resolve(ctx, doc, opts)
}

// bindingDTO is the wire shape returned by both REST and MCP for a single
// binding row.
type bindingDTO struct {
	Variable     string `json:"variable"`
	SourceKind   string `json:"source_kind"`
	SourceRef    string `json:"source_ref,omitempty"`
	SourcePath   string `json:"source_path,omitempty"`
	Fallback     string `json:"fallback,omitempty"`
	LastValue    string `json:"last_value,omitempty"`
	LastResolved string `json:"last_resolved,omitempty"`
	LastError    string `json:"last_error,omitempty"`
	UpdatedAt    string `json:"updated_at"`
}

func bindingToDTO(b *generated.DocumentVariableBinding) bindingDTO {
	out := bindingDTO{
		Variable:   b.VariableName,
		SourceKind: b.SourceKind,
		SourceRef:  b.SourceRef,
		SourcePath: b.SourcePath,
		Fallback:   b.Fallback,
		LastValue:  b.LastValue,
		LastError:  b.LastError,
		UpdatedAt:  b.UpdatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if b.LastResolved.Valid {
		out.LastResolved = b.LastResolved.Time.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return out
}

// GET /api/v1/documents/{id}/variable-bindings
func (s *Server) handleListVariableBindings(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
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
	rows, err := s.Queries.ListVariableBindings(r.Context(), docID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]bindingDTO, 0, len(rows))
	for _, b := range rows {
		out = append(out, bindingToDTO(b))
	}
	writeJSON(w, http.StatusOK, map[string]any{"bindings": out, "count": len(out)})
}

// PUT /api/v1/documents/{id}/variable-bindings/{name}
//
// Body: { "source_kind": "...", "source_ref": "...", "source_path": "...", "fallback": "..." }
func (s *Server) handleUpsertVariableBinding(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "variable name required")
		return
	}
	var in struct {
		SourceKind string `json:"source_kind"`
		SourceRef  string `json:"source_ref"`
		SourcePath string `json:"source_path"`
		Fallback   string `json:"fallback"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if !resolver.SourceKind(in.SourceKind).Valid() {
		writeError(w, http.StatusBadRequest, "unknown source_kind")
		return
	}
	doc, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: sess.OrgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	if doc.Status != "draft" {
		writeError(w, http.StatusConflict, "bindings can only be edited on draft documents")
		return
	}
	row, err := s.Queries.UpsertVariableBinding(r.Context(), generated.UpsertVariableBindingParams{
		DocumentID:   docID,
		VariableName: name,
		SourceKind:   in.SourceKind,
		SourceRef:    in.SourceRef,
		SourcePath:   in.SourcePath,
		Fallback:     in.Fallback,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID:       sess.OrgID,
		ActorUserID: &sess.UserID,
		DocumentID:  &docID,
		Kind:        audit.KindDocumentUpdated,
		IP:          firstIPFromHeader(r),
		UserAgent:   r.UserAgent(),
		Payload: map[string]any{
			"via":         "rest",
			"tool":        "upsert_variable_binding",
			"variable":    name,
			"source_kind": in.SourceKind,
		},
	})
	writeJSON(w, http.StatusOK, bindingToDTO(row))
}

// DELETE /api/v1/documents/{id}/variable-bindings/{name}
func (s *Server) handleDeleteVariableBinding(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "variable name required")
		return
	}
	doc, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: sess.OrgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	if doc.Status != "draft" {
		writeError(w, http.StatusConflict, "bindings can only be edited on draft documents")
		return
	}
	if err := s.Queries.DeleteVariableBinding(r.Context(), generated.DeleteVariableBindingParams{
		DocumentID:   docID,
		VariableName: name,
	}); err != nil {
		writeInternalError(w, err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID:       sess.OrgID,
		ActorUserID: &sess.UserID,
		DocumentID:  &docID,
		Kind:        audit.KindDocumentUpdated,
		IP:          firstIPFromHeader(r),
		UserAgent:   r.UserAgent(),
		Payload:     map[string]any{"via": "rest", "tool": "delete_variable_binding", "variable": name},
	})
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/v1/documents/{id}/resolve-preview
//
// Returns the resolved variable map plus a per-binding ResolveReport so the
// editor can display "var X resolved from CRM, var Y from fallback" without
// running its own resolver client-side.
func (s *Server) handleResolvePreview(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	doc, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: sess.OrgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	resolved, report, err := s.resolveVariables(r.Context(), doc)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"variables": resolved,
		"report":    report,
		"frozen":    doc.Status != "draft",
	})
}
