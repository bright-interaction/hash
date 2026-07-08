package handler

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/evidence"
)

// Phase 10.2: court-ready evidence bundle export. Returns a single PDF
// with the signed document as the visible body and attached files for
// machine readers (manifest.json, events.json, versions.json,
// public-key.pem, optional cert.ots).

// GET /api/v1/documents/{id}/evidence-bundle
func (s *Server) handleEvidenceBundle(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	// The downloadable evidence bundle is a paid-plan feature. The key MUST match the
	// one seeded into billing_plans.features_json ("evidence_bundle"); the old
	// "evidence" key matched no plan, so HasFeature was always false and this flagship
	// feature returned 402 for every customer, paid included.
	if !s.requireFeature(w, r, sess.OrgID, "evidence_bundle") {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
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
	if s.Evidence == nil {
		writeError(w, http.StatusServiceUnavailable, "evidence builder not configured")
		return
	}
	res, err := s.Evidence.Build(r.Context(), doc)
	if err != nil {
		if errors.Is(err, evidence.ErrNotTerminal) {
			writeError(w, http.StatusConflict, "evidence bundle only available for terminal documents (completed, declined, voided, expired)")
			return
		}
		writeInternalError(w, err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID:       sess.OrgID,
		ActorUserID: &sess.UserID,
		DocumentID:  &doc.ID,
		Kind:        audit.KindDocumentUpdated, // closest existing enum; bundle-export taxonomy can land in 10.2.1
		IP:          firstIPFromHeader(r),
		UserAgent:   r.UserAgent(),
		Payload: map[string]any{
			"via":               "rest",
			"tool":              "evidence_bundle_export",
			"final_pdf_sha256":  res.Manifest.FinalPDFSHA256,
			"manifest_anchored": res.Manifest.OpenTimestamps != nil,
		},
	})
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, res.Filename))
	_, _ = w.Write(res.Bytes)
}

// GET /api/v1/documents/{id}/evidence-manifest
//
// Returns just the manifest JSON, without rebuilding the PDF. Cheap
// preview path for the UI before committing to the full bundle
// download.
func (s *Server) handleEvidenceManifest(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
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
	if s.Evidence == nil {
		writeError(w, http.StatusServiceUnavailable, "evidence builder not configured")
		return
	}
	res, err := s.Evidence.Build(r.Context(), doc)
	if err != nil {
		if errors.Is(err, evidence.ErrNotTerminal) {
			writeError(w, http.StatusConflict, "manifest only available for terminal documents")
			return
		}
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res.Manifest)
}
