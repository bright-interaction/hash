// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/i18n"
	"github.com/bright-interaction/hash/internal/sign"
)

// Magic-link signer handlers. No session auth; the URL token IS the auth.
//
// Routes:
//   GET  /sign/{token}                 → recipient + document context (JSON)
//   GET  /sign/{token}/document        → rendered HTML preview (browser display)
//   POST /sign/{token}/view            → idempotent view-tracking ping
//   POST /sign/{token}/sign            → finalize signature
//   POST /sign/{token}/decline         → decline with reason

type signerContextResponse struct {
	DocumentID        uuid.UUID `json:"document_id"`
	DocumentName      string    `json:"document_name"`
	Status            string    `json:"status"`
	SourceKind        string    `json:"source_kind"`
	RequiresSignature bool      `json:"requires_signature"`
	RoutingTier       string    `json:"routing_tier"`
	QESProvider       string    `json:"qes_provider,omitempty"`
	Recipient         struct {
		ID     uuid.UUID `json:"id"`
		Email  string    `json:"email"`
		Name   string    `json:"name"`
		Role   string    `json:"role"`
		Status string    `json:"status"`
		Locale string    `json:"locale"`
	} `json:"recipient"`
	Fonts []string `json:"fonts"`

	// Privacy is the GDPR Article 13 transparency payload the signer
	// page renders inline. Surfacing it here (rather than only on a
	// remote /legal/privacy page) means the recipient sees who is
	// processing their data at the moment of collection, not buried
	// in a footer link.
	Privacy signerPrivacyNotice `json:"privacy"`
}

type signerPrivacyNotice struct {
	Controller     string `json:"controller"`      // sender org name
	Processor      string `json:"processor"`       // Hash instance owner
	ProcessorEmail string `json:"processor_email"` // DPO contact
	PurposeSummary string `json:"purpose_summary"`
	LegalBasis     string `json:"legal_basis"` // GDPR Art. 6 cite
	RetentionYears int    `json:"retention_years"`
	JurisdictionDP string `json:"jurisdiction_dp"` // supervisory authority
	PolicyURL      string `json:"policy_url"`
	DSREndpoint    string `json:"dsr_endpoint"` // POST /sign/{token}/dsr
}

// handleSignerRoot serves GET /sign/{token}. A browser navigating to the magic
// link wants the SPA signer ceremony page (HTML); the SPA itself then fetches the
// same URL for the JSON context. Both hit this bare path (the SPA calls
// fetch(`/sign/${token}`)), and StripSlashes collapses the trailing slash, so the
// API route would otherwise shadow the page and the signer would see raw JSON.
// Branch on the request: a top-level document navigation gets the SPA shell, an
// XHR/fetch (or any non-browser client) gets the JSON context.
func (s *Server) handleSignerRoot(w http.ResponseWriter, r *http.Request) {
	if s.Frontend != nil && isDocumentNavigation(r) {
		s.Frontend.ServeHTTP(w, r)
		return
	}
	s.handleSignerContext(w, r)
}

// isDocumentNavigation reports whether the request is a top-level browser page
// navigation (vs an XHR/fetch). Prefers the Sec-Fetch-Dest hint (sent by all
// modern browsers); falls back to the Accept header. The SPA's fetch() sends
// Accept: */* and Sec-Fetch-Dest: empty, so it is correctly treated as an API call.
func isDocumentNavigation(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "document":
		return true
	case "empty", "cors", "websocket":
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func (s *Server) handleSignerContext(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	out := signerContextResponse{
		DocumentID:        rc.Document.ID,
		DocumentName:      rc.Document.Name,
		Status:            rc.Document.Status,
		SourceKind:        rc.Document.SourceKind,
		RequiresSignature: rc.Document.RequiresSignature,
		RoutingTier:       rc.Document.RoutingTier,
		Fonts:             []string{"Caveat", "Dancing Script", "Great Vibes", "Sacramento", "Homemade Apple"},
	}
	if s.QES != nil && s.QES.Provider != nil && s.QES.Provider.Name() != "noop" {
		out.QESProvider = s.QES.Provider.Name()
	}
	out.Recipient.ID = rc.Recipient.ID
	out.Recipient.Email = rc.Recipient.Email
	out.Recipient.Name = rc.Recipient.Name
	out.Recipient.Role = rc.Recipient.Role
	out.Recipient.Status = rc.Recipient.Status
	out.Recipient.Locale = rc.Recipient.Locale
	controller := s.OrgName
	if controller == "" {
		controller = "the sender"
	}
	loc := i18n.Normalize(rc.Recipient.Locale)
	out.Privacy = signerPrivacyNotice{
		Controller:     controller,
		Processor:      "Bright Interaction AB",
		ProcessorEmail: "privacy@brightinteraction.com",
		PurposeSummary: i18n.T(loc, "privacy.purpose", nil),
		LegalBasis:     i18n.T(loc, "privacy.legalBasis", nil),
		RetentionYears: 7,
		JurisdictionDP: "Integritetsskyddsmyndigheten (IMY), Sweden",
		PolicyURL:      "/legal/privacy",
		DSREndpoint:    "/sign/" + chi.URLParam(r, "token") + "/dsr",
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSignerDocument(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	if rc.Document.SourceKind != "blocks" {
		writeError(w, http.StatusBadRequest, "pdf-source documents not yet renderable inline")
		return
	}
	// Reuse the same renderer the sender preview uses, so the signer sees
	// exactly what the sender approved (variables + conditionals applied).
	html, err := s.Sign.RenderForSigner(r.Context(), rc)
	if err != nil {
		writeInternalErrorMsg(w, "render preview", err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

func (s *Server) handleSignerView(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	if err := s.Sign.MarkViewed(r.Context(), rc, clientIP(r), r.UserAgent()); err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "viewed"})
}

type signerSignInput struct {
	TypedName string `json:"typed_name"`
	Font      string `json:"font"`
}

type signerSignResponse struct {
	Status      string `json:"status"`
	Completed   bool   `json:"completed"`
	FinalPDFURL string `json:"final_pdf_url,omitempty"`
}

func (s *Server) handleSignerSign(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	var in signerSignInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.Sign.Sign(r.Context(), rc, sign.SignInput{
		TypedName: in.TypedName,
		Font:      in.Font,
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		switch {
		case errors.Is(err, sign.ErrAlreadySigned):
			writeError(w, http.StatusConflict, "you have already signed this document")
		case errors.Is(err, sign.ErrDocumentNotSignable):
			writeError(w, http.StatusConflict, "this document is no longer accepting signatures")
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	out := signerSignResponse{
		Status:    res.Status,
		Completed: res.Completed,
	}
	if res.Completed {
		// 24-hour presigned download for the final PDF.
		if u, err := s.Storage.PresignGet(r.Context(), res.FinalPDFKey, 24*time.Hour); err == nil {
			out.FinalPDFURL = u.String()
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSignerAccept records a recipient's acknowledgement (accept) of a
// no-signature document. The audit event is the record; no signature is captured.
func (s *Server) handleSignerAccept(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	res, err := s.Sign.Accept(r.Context(), rc, clientIP(r), r.UserAgent())
	if err != nil {
		switch {
		case errors.Is(err, sign.ErrAlreadyAccepted):
			writeError(w, http.StatusConflict, "you have already accepted this document")
		case errors.Is(err, sign.ErrNotAcknowledgement):
			writeError(w, http.StatusBadRequest, "this document requires a signature")
		case errors.Is(err, sign.ErrDocumentNotSignable):
			writeError(w, http.StatusConflict, "this document is no longer accepting responses")
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	out := signerSignResponse{Status: res.Status, Completed: res.Completed}
	if res.Completed && res.FinalPDFKey != "" {
		if u, err := s.Storage.PresignGet(r.Context(), res.FinalPDFKey, 24*time.Hour); err == nil {
			out.FinalPDFURL = u.String()
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type signerDeclineInput struct {
	Reason string `json:"reason"`
}

func (s *Server) handleSignerDecline(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	var in signerDeclineInput
	_ = decodeJSON(r, &in)
	if err := s.Sign.Decline(r.Context(), rc, in.Reason, clientIP(r), r.UserAgent()); err != nil {
		switch {
		case errors.Is(err, sign.ErrDocumentNotSignable):
			writeError(w, http.StatusConflict, "this document is no longer accepting changes")
		case errors.Is(err, sign.ErrAlreadySigned):
			writeError(w, http.StatusConflict, "you have already signed this document")
		default:
			writeInternalError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "declined"})
}

type signerRequestChangesInput struct {
	Message  string `json:"message"`
	BlockID  string `json:"block_id"`
	Quote    string `json:"quote"`
	Context  string `json:"context"`
	Proposed string `json:"proposed"`
}

func (s *Server) handleSignerRequestChanges(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	var in signerRequestChangesInput
	_ = decodeJSON(r, &in)
	if err := s.Sign.RequestChanges(r.Context(), rc, sign.ChangeRequestInput{
		Message:   in.Message,
		BlockID:   in.BlockID,
		Quote:     in.Quote,
		Context:   in.Context,
		Proposed:  in.Proposed,
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
	}); err != nil {
		switch {
		case errors.Is(err, sign.ErrDocumentNotSignable):
			writeError(w, http.StatusConflict, "this document is no longer accepting changes")
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "changes_requested"})
}

func (s *Server) handleSignerListComments(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	rows, err := s.Queries.ListComments(r.Context(), rc.Document.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list comments failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"comments": toCommentResponses(rows)})
}

func (s *Server) handleSignerCreateComment(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	var in createCommentInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	c, err := s.Sign.SignerComment(r.Context(), rc, in.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, toCommentResponse(c))
}

// handleSignerFinalPDF streams the signed PDF to any recipient via their magic
// link once the document is completed. The presigned URL handleSignerSign
// returns is ephemeral and only the final signer ever receives it; this stable
// route gives every signer (and anyone re-opening their link afterwards) a way
// to retrieve their copy.
func (s *Server) handleSignerFinalPDF(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	if rc.Document.Status != "completed" || !rc.Document.FinalPdfKey.Valid {
		writeError(w, http.StatusNotFound, "signed pdf not available yet")
		return
	}
	body, err := s.Storage.Get(r.Context(), rc.Document.FinalPdfKey.String)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFileName(rc.Document.Name)+`.pdf"`)
	_, _ = w.Write(body)
}

// handleSignerPDF serves the original uploaded PDF of a pdf-source document to
// the signer (magic-token authed) so the signer page can render its pages with
// pdf.js and overlay the fillable fields.
func (s *Server) handleSignerPDF(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	if !rc.Document.PdfStorageKey.Valid || rc.Document.PdfStorageKey.String == "" {
		writeError(w, http.StatusNotFound, "document has no source pdf")
		return
	}
	body, err := s.Storage.Get(r.Context(), rc.Document.PdfStorageKey.String)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "inline")
	_, _ = w.Write(body)
}

// lookupTokenOrError verifies the URL token and writes 404 on miss. Returns
// (recipientContext, true) on success.
func (s *Server) lookupTokenOrError(w http.ResponseWriter, r *http.Request) (*sign.RecipientContext, bool) {
	tok := chi.URLParam(r, "token")
	if tok == "" {
		writeError(w, http.StatusBadRequest, "missing token")
		return nil, false
	}
	hash := auth.HashMagicToken(tok)
	rc, err := s.Sign.LookupByToken(r.Context(), hash)
	if errors.Is(err, sign.ErrMagicLinkExpired) {
		// 410 Gone signals "this resource existed and is permanently
		// gone" so the signer UI can show "this link expired" copy
		// instead of the generic "invalid" copy that 404 implies.
		writeError(w, http.StatusGone, "magic link expired")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusNotFound, "invalid or expired link")
		return nil, false
	}
	return rc, true
}

// handleFinalPDF lets the sender download the final PDF (session-auth).
func (s *Server) handleFinalPDF(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	doc, err := s.Queries.GetDocument(r.Context(), docGetParams(docID, u.OrgID))
	if err != nil {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if !doc.FinalPdfKey.Valid {
		writeError(w, http.StatusNotFound, "final pdf not yet rendered")
		return
	}
	body, err := s.Storage.Get(r.Context(), doc.FinalPdfKey.String)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFileName(doc.Name)+`.pdf"`)
	_, _ = w.Write(body)
}

// handleAuditCert downloads the audit certificate PDF.
func (s *Server) handleAuditCert(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	doc, err := s.Queries.GetDocument(r.Context(), docGetParams(docID, u.OrgID))
	if err != nil {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if !doc.AuditCertKey.Valid {
		writeError(w, http.StatusNotFound, "audit certificate not yet rendered")
		return
	}
	body, err := s.Storage.Get(r.Context(), doc.AuditCertKey.String)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFileName(doc.Name)+`-audit.pdf"`)
	_, _ = w.Write(body)
}

func sanitizeFileName(name string) string {
	if name == "" {
		return "document"
	}
	// Strip path separators + non-printable. Spaces stay.
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r == '/' || r == '\\':
			// drop
		case r < 0x20:
			// drop control chars
		default:
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return "document"
	}
	return string(out)
}

// guards against unused import errors when the path import is referenced
// only inside generic helpers above.
var _ = path.Join
var _ = errors.New
var _ = pgtype.Text{}
