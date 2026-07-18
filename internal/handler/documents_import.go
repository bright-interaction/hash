// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/google/uuid"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/docintake"
	"github.com/brightinteraction/hash/internal/render"
)

// maxProposalHTML caps the JSON body for the HTML intake path. A designed
// proposal can legitimately embed fonts/images as data: URIs, so it is far
// larger than the 1 MB decodeJSON cap but still bounded.
const maxProposalHTML = 20 << 20 // 20 MB

// importProposalInput is the JSON body for POST /documents/import when the
// caller supplies a designed HTML page to render into a signable PDF.
type importProposalInput struct {
	Name      string `json:"name"`
	HTML      string `json:"html"`
	Landscape bool   `json:"landscape,omitempty"`
}

// handleImportDocument creates a pdf-source document in ONE step, skipping the
// template detour, from either:
//
//   - multipart/form-data with a "pdf" file part  -> the upload is the document
//   - application/json {name, html}               -> the HTML is rendered to a
//     PDF by Gotenberg (design preserved) and becomes the document
//
// Both land as source_kind=pdf, so the existing field designer + sign +
// stamp/seal path take over unchanged. This is the "designed proposal that is
// signable" intake.
func (s *Server) handleImportDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if ct := r.Header.Get("Content-Type"); ct == "application/json" || ct == "application/json; charset=utf-8" {
		s.importDocumentFromHTML(w, r, u.UserID, u.OrgID)
		return
	}
	s.importDocumentFromPDF(w, r, u.UserID, u.OrgID)
}

func (s *Server) importDocumentFromPDF(w http.ResponseWriter, r *http.Request, userID, orgID uuid.UUID) {
	r.Body = http.MaxBytesReader(w, r.Body, maxPDFUpload+(1<<20))
	if err := r.ParseMultipartForm(maxPDFUpload); err != nil {
		writeError(w, http.StatusBadRequest, "could not parse upload: "+err.Error())
		return
	}
	name := r.FormValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	file, _, err := r.FormFile("pdf")
	if err != nil {
		writeError(w, http.StatusBadRequest, "pdf file required (form field 'pdf')")
		return
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read upload failed")
		return
	}
	if !looksLikePDF(data) {
		writeError(w, http.StatusBadRequest, "uploaded file is not a PDF (magic bytes mismatch)")
		return
	}
	s.finishPDFDocument(w, r, userID, orgID, name, data)
}

func (s *Server) importDocumentFromHTML(w http.ResponseWriter, r *http.Request, userID, orgID uuid.UUID) {
	if s.Sign == nil || s.Sign.PDF == nil {
		writeError(w, http.StatusServiceUnavailable, "pdf renderer unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxProposalHTML)
	var in importProposalInput
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if in.HTML == "" {
		writeError(w, http.StatusBadRequest, "html required")
		return
	}
	// Preserve the page's design; strip only the JS + remote-fetch (SSRF)
	// surface before Chromium sees it.
	safe := render.SanitizeForRender(in.HTML)
	opts := render.PDFOptions{
		PreferCSSPageSize: true,
		WaitDelay:         "1000ms",
	}
	if in.Landscape {
		opts.PaperWidth, opts.PaperHeight = 11.69, 8.27 // A4 landscape fallback when the HTML sets no @page size
	}
	pdfBytes, err := s.Sign.PDF.HTMLToPDF(r.Context(), safe, opts)
	if err != nil {
		writeInternalErrorMsg(w, "render html to pdf failed", err)
		return
	}
	s.finishPDFDocument(w, r, userID, orgID, in.Name, pdfBytes)
}

// finishPDFDocument runs the shared clean+store+create intake, then does the
// HTTP + audit bookkeeping.
func (s *Server) finishPDFDocument(w http.ResponseWriter, r *http.Request, userID, orgID uuid.UUID, name string, data []byte) {
	d, pageCount, err := docintake.CreatePDFSourceDocument(r.Context(), s.Queries, s.Storage, orgID, userID, name, data)
	if err != nil {
		if errors.Is(err, docintake.ErrSanitizePDF) {
			writeError(w, http.StatusBadRequest, "sanitize PDF: "+err.Error())
			return
		}
		if errors.Is(err, docintake.ErrTooManyPages) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeInternalErrorMsg(w, "create document failed", err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: orgID, ActorUserID: &userID, DocumentID: &d.ID,
		Kind:    audit.KindDocumentCreated,
		Payload: map[string]any{"name": name, "source_kind": "pdf", "intake": "import"},
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"document":   toDocumentResponse(d),
		"page_count": pageCount,
	})
}
