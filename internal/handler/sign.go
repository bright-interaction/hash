// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"path"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/auth"
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
	Controller        string                   `json:"controller"`         // sender org name frozen at send
	ControllerContact string                   `json:"controller_contact"` // sending controller contact frozen at send
	Processor         string                   `json:"processor"`          // Hash instance owner
	ProcessorEmail    string                   `json:"processor_email"`    // DPO contact
	PurposeSummary    string                   `json:"purpose_summary"`
	LegalBasis        string                   `json:"legal_basis"` // document-specific controller selection
	RetentionYears    int                      `json:"retention_years"`
	JurisdictionDP    string                   `json:"jurisdiction_dp"` // supervisory authority
	PolicyURL         string                   `json:"policy_url"`
	DSREndpoint       string                   `json:"dsr_endpoint"`  // POST /sign/{token}/dsr
	NoticeDigest      string                   `json:"notice_digest"` // changes whenever material notice/ceremony context changes
	Copy              sign.Article13NoticeCopy `json:"copy"`
}

// signerNoticeDigestHeader carries the exact server-authored notice digest on
// each participant mutation. It is evidence metadata rather than a credential;
// the URL token remains the sole bearer secret.
const signerNoticeDigestHeader = "X-Hash-Notice-Digest"

// requireSignerNoticeAcknowledgement closes the direct-POST bypass around the
// signer page's Article 13 gate. The canonical server digest (not the untrusted
// header value) and its canonical snapshot are returned for binding into the
// resulting durable audit evidence.
func (s *Server) requireSignerNoticeAcknowledgement(w http.ResponseWriter, r *http.Request, rc *sign.RecipientContext) (sign.Article13NoticeEvidence, bool) {
	notice, err := s.signerPrivacyNotice(r, rc)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		return sign.Article13NoticeEvidence{}, false
	}
	evidence, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		return sign.Article13NoticeEvidence{}, false
	}
	digest := evidence.Digest
	values := r.Header.Values(signerNoticeDigestHeader)
	if digest == "" || digest != notice.NoticeDigest || len(values) != 1 || subtle.ConstantTimeCompare([]byte(values[0]), []byte(digest)) != 1 {
		writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		return sign.Article13NoticeEvidence{}, false
	}
	return evidence, true
}

func bindSignerNoticeAuditPayload(notice sign.Article13NoticeEvidence, payload map[string]any) (map[string]any, error) {
	if payload == nil {
		payload = make(map[string]any)
	}
	if err := notice.BindAuditPayload(payload); err != nil {
		return nil, err
	}
	return payload, nil
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
	out.Recipient.ID = rc.Recipient.ID
	out.Recipient.Email = rc.Recipient.Email
	out.Recipient.Name = rc.Recipient.Name
	out.Recipient.Role = rc.Recipient.Role
	out.Recipient.Status = rc.Recipient.Status
	out.Recipient.Locale = rc.Recipient.Locale
	privacy, err := s.signerPrivacyNotice(r, rc)
	if err != nil {
		// A valid signer token without a trustworthy customer-controller
		// identity must not render a legally misleading Article 13 notice.
		writeError(w, http.StatusNotFound, "invalid or expired link")
		return
	}
	out.Privacy = privacy
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) signerPrivacyNotice(r *http.Request, rc *sign.RecipientContext) (signerPrivacyNotice, error) {
	if rc == nil || rc.Recipient == nil || rc.Document == nil || rc.ControllerOrg == nil ||
		rc.ControllerOrg.ID != rc.Document.OrgID {
		return signerPrivacyNotice{}, sign.ErrSignerControllerUnavailable
	}
	confirmation := rc.LawfulBasisConfirmation
	if confirmation == nil || !confirmation.ConfirmedAt.Valid ||
		confirmation.DocumentID != rc.Document.ID || confirmation.OrgID != rc.Document.OrgID ||
		strings.TrimSpace(confirmation.LawfulBasis) != strings.TrimSpace(rc.Document.LawfulBasis) ||
		strings.TrimSpace(confirmation.ControllerName) == "" ||
		strings.TrimSpace(confirmation.ControllerContact) == "" {
		return signerPrivacyNotice{}, sign.ErrSignerLawfulBasisUnavailable
	}
	controller := strings.TrimSpace(confirmation.ControllerName)
	controllerContact := strings.TrimSpace(confirmation.ControllerContact)
	legalBasis, err := article13.LegalBasisDisclosureV1(rc.Document.LawfulBasis)
	if err != nil {
		return signerPrivacyNotice{}, err
	}
	operator := strings.TrimSpace(s.OperatorName)
	privacyContact := strings.TrimSpace(s.PrivacyContact)
	supervisoryAuthority := strings.TrimSpace(s.SupervisoryAuthority)
	policyURL := strings.TrimSpace(s.PrivacyPolicyURL)
	if operator == "" || privacyContact == "" || supervisoryAuthority == "" || policyURL == "" {
		return signerPrivacyNotice{}, errors.New("signer privacy disclosure instance identity is unavailable")
	}
	if !rc.Document.SentAt.Valid || rc.Document.SentAt.Time.IsZero() {
		return signerPrivacyNotice{}, sign.ErrSignerLawfulBasisUnavailable
	}
	notice := signerPrivacyNotice{
		Controller:        controller,
		ControllerContact: controllerContact,
		Processor:         operator,
		ProcessorEmail:    privacyContact,
		// The signer SPA is intentionally English-only until every legal string
		// has received counsel-reviewed translations. Keep the server-authored
		// disclosure in that same language so the ceremony cannot mix locales.
		PurposeSummary: article13.PurposeSummaryV1(rc.Document.Name),
		LegalBasis:     legalBasis,
		RetentionYears: article13.RetentionYearsV1,
		JurisdictionDP: supervisoryAuthority,
		PolicyURL:      policyURL,
		DSREndpoint:    "/sign/" + chi.URLParam(r, "token") + "/dsr",
	}
	notice.Copy = article13.RenderedCopyV1(rc.Document.Name)
	evidence, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		return signerPrivacyNotice{}, errors.New("signer privacy disclosure digest is unavailable")
	}
	notice.NoticeDigest = evidence.Digest
	return notice, nil
}

func signerArticle13NoticeEvidence(rc *sign.RecipientContext, notice signerPrivacyNotice) (sign.Article13NoticeEvidence, error) {
	if rc == nil || rc.Document == nil || rc.Recipient == nil {
		return sign.Article13NoticeEvidence{}, sign.ErrInvalidNoticeEvidence
	}
	snapshot, err := article13.NewSnapshotForSchema(rc.Document.Article13NoticeSchema, article13.Input{
		DocumentID: rc.Document.ID, OrgID: rc.Document.OrgID, RecipientID: rc.Recipient.ID,
		SentAt:     rc.Document.SentAt.Time,
		Controller: notice.Controller, ControllerContact: notice.ControllerContact,
		Processor: notice.Processor, ProcessorContact: notice.ProcessorEmail,
		PurposeSummary: notice.PurposeSummary, LegalBasisDisclosure: notice.LegalBasis,
		RetentionYears: notice.RetentionYears, SupervisoryAuthority: notice.JurisdictionDP,
		PolicyURL: notice.PolicyURL, DSRCapability: article13.DSRCapabilitySignerRequest,
		Copy: notice.Copy,
	})
	if err != nil {
		return sign.Article13NoticeEvidence{}, err
	}
	return article13.NewEvidence(snapshot)
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
	noticeEvidence, ok := s.requireSignerNoticeAcknowledgement(w, r, rc)
	if !ok {
		return
	}
	if err := s.Sign.MarkViewed(r.Context(), rc, sign.ParticipantResponseEvidence{
		IP: clientIP(r), UserAgent: r.UserAgent(), Notice: noticeEvidence,
	}); err != nil {
		if errors.Is(err, sign.ErrInvalidNoticeEvidence) {
			writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
			return
		}
		if errors.Is(err, sign.ErrDocumentNotSignable) {
			writeError(w, http.StatusConflict, "this document is no longer active")
			return
		}
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
	noticeEvidence, ok := s.requireSignerNoticeAcknowledgement(w, r, rc)
	if !ok {
		return
	}
	var in signerSignInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.Sign.Sign(r.Context(), rc, sign.SignInput{
		TypedName: in.TypedName,
		Font:      in.Font,
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
		Notice:    noticeEvidence,
	})
	if err != nil {
		switch {
		case errors.Is(err, sign.ErrInvalidNoticeEvidence):
			writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		case errors.Is(err, sign.ErrSignatureTierUnavailable):
			writeError(w, http.StatusConflict, "AES and QES signing are temporarily unavailable; this document cannot be completed through the SES endpoint")
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
		Status:      res.Status,
		Completed:   res.Completed,
		FinalPDFURL: res.FinalPDFURL,
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSignerAccept records a recipient's acknowledgement (accept) of a
// no-signature document. The audit event is the record; no signature is captured.
type signerAcceptInput struct{}

func (s *Server) handleSignerAccept(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	noticeEvidence, ok := s.requireSignerNoticeAcknowledgement(w, r, rc)
	if !ok {
		return
	}
	var in signerAcceptInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.Sign.Accept(r.Context(), rc, sign.ParticipantResponseEvidence{
		IP: clientIP(r), UserAgent: r.UserAgent(), Notice: noticeEvidence,
	})
	if err != nil {
		switch {
		case errors.Is(err, sign.ErrInvalidNoticeEvidence):
			writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		case errors.Is(err, sign.ErrSignatureTierUnavailable):
			writeError(w, http.StatusConflict, "AES and QES response flows are temporarily unavailable")
		case errors.Is(err, sign.ErrAlreadyAccepted):
			writeError(w, http.StatusConflict, "you have already accepted this document")
		case errors.Is(err, sign.ErrNotAcknowledgement):
			writeError(w, http.StatusBadRequest, "this document requires a signature")
		case errors.Is(err, sign.ErrRecipientNotEligibleForResponse):
			writeError(w, http.StatusForbidden, "this recipient role cannot acknowledge the document")
		case errors.Is(err, sign.ErrDocumentNotSignable):
			writeError(w, http.StatusConflict, "this document is no longer accepting responses")
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	out := signerSignResponse{Status: res.Status, Completed: res.Completed, FinalPDFURL: res.FinalPDFURL}
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
	noticeEvidence, ok := s.requireSignerNoticeAcknowledgement(w, r, rc)
	if !ok {
		return
	}
	var in signerDeclineInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Sign.Decline(r.Context(), rc, in.Reason, sign.ParticipantResponseEvidence{
		IP: clientIP(r), UserAgent: r.UserAgent(), Notice: noticeEvidence,
	}); err != nil {
		switch {
		case errors.Is(err, sign.ErrInvalidNoticeEvidence):
			writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		case errors.Is(err, sign.ErrEnvelopeTransitionUnsupported):
			writeError(w, http.StatusConflict, "declining an envelope is not supported; ask the sender to void the envelope")
		case errors.Is(err, sign.ErrDocumentNotSignable):
			writeError(w, http.StatusConflict, "this document is no longer accepting changes")
		case errors.Is(err, sign.ErrAlreadySigned):
			writeError(w, http.StatusConflict, "you have already signed this document")
		case errors.Is(err, sign.ErrAlreadyAccepted):
			writeError(w, http.StatusConflict, "you have already acknowledged this document")
		case errors.Is(err, sign.ErrRecipientNotEligibleForResponse):
			writeError(w, http.StatusForbidden, "this recipient role cannot decline the document")
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
	noticeEvidence, ok := s.requireSignerNoticeAcknowledgement(w, r, rc)
	if !ok {
		return
	}
	var in signerRequestChangesInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Sign.RequestChanges(r.Context(), rc, sign.ChangeRequestInput{
		Message:   in.Message,
		BlockID:   in.BlockID,
		Quote:     in.Quote,
		Context:   in.Context,
		Proposed:  in.Proposed,
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
		Notice:    noticeEvidence,
	}); err != nil {
		switch {
		case errors.Is(err, sign.ErrInvalidNoticeEvidence):
			writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		case errors.Is(err, sign.ErrEnvelopeTransitionUnsupported):
			writeError(w, http.StatusConflict, "change requests are not supported for envelopes")
		case errors.Is(err, sign.ErrRevisionWouldDestroyEvidence):
			writeError(w, http.StatusConflict, "changes cannot be requested after a legal response has been captured")
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
	noticeEvidence, ok := s.requireSignerNoticeAcknowledgement(w, r, rc)
	if !ok {
		return
	}
	var in createCommentInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	c, err := s.Sign.SignerComment(r.Context(), rc, in.Body, sign.ParticipantResponseEvidence{
		IP: clientIP(r), UserAgent: r.UserAgent(), Notice: noticeEvidence,
	})
	if err != nil {
		if errors.Is(err, sign.ErrInvalidNoticeEvidence) {
			writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
			return
		}
		if errors.Is(err, sign.ErrDocumentNotSignable) || errors.Is(err, sign.ErrDocumentNotCommentable) {
			writeError(w, http.StatusConflict, "this document is not accepting comments")
			return
		}
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
	tok := chi.URLParam(r, "token")
	if tok == "" {
		writeError(w, http.StatusBadRequest, "missing token")
		return
	}
	// Completion atomically expires every mutation credential. The final PDF
	// is the sole exception: a recipient who actually signed/accepted keeps
	// read-only access through the same stable link shown by the ceremony UI.
	rc, err := s.Sign.LookupCompletedArtifactByToken(r.Context(), auth.HashMagicToken(tok))
	if err != nil {
		writeError(w, http.StatusNotFound, "signed pdf not available")
		return
	}
	body, err := readDocumentArtifact(r.Context(), s.Storage, rc.Document, rc.Document.FinalPdfKey.String, rc.Document.FinalPdfSha, rc.Document.FinalPdfVersionID)
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
	body, err := readDocumentArtifact(r.Context(), s.Storage, rc.Document, rc.Document.PdfStorageKey.String, rc.Document.PdfSha256, rc.Document.PdfStorageVersionID)
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
	body, err := readDocumentArtifact(r.Context(), s.Storage, doc, doc.FinalPdfKey.String, doc.FinalPdfSha, doc.FinalPdfVersionID)
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
	certDigest := doc.AuditCertSha256
	if len(certDigest) != sha256.Size && !doc.EvidenceVersionPinsRequired {
		certDigest = contentAddressedDigest(doc.AuditCertKey.String, "audit", ".pdf")
	}
	body, err := readDocumentArtifact(r.Context(), s.Storage, doc, doc.AuditCertKey.String, certDigest, doc.AuditCertVersionID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if !contentAddressedArtifactMatches(body, doc.AuditCertKey.String, "audit", ".pdf") {
		writeInternalError(w, errors.New("stored audit certificate digest does not match its immutable key"))
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFileName(doc.Name)+`-audit.pdf"`)
	_, _ = w.Write(body)
}

func finalPDFMatchesDigest(body, expected []byte) bool {
	if len(expected) != sha256.Size {
		return false
	}
	actual := sha256.Sum256(body)
	return bytes.Equal(actual[:], expected)
}

// contentAddressedArtifactMatches verifies new immutable keys while preserving
// downloads for historical rows whose legacy key did not encode a digest.
func contentAddressedArtifactMatches(body []byte, key, prefix, suffix string) bool {
	name := path.Base(key)
	marker := prefix + "-"
	if !strings.HasPrefix(name, marker) || !strings.HasSuffix(name, suffix) {
		return true
	}
	rawHex := strings.TrimSuffix(strings.TrimPrefix(name, marker), suffix)
	if len(rawHex) != sha256.Size*2 {
		return false
	}
	expected, err := hex.DecodeString(rawHex)
	if err != nil {
		return false
	}
	actual := sha256.Sum256(body)
	return bytes.Equal(actual[:], expected)
}

func contentAddressedDigest(key, prefix, suffix string) []byte {
	name := path.Base(key)
	marker := prefix + "-"
	if !strings.HasPrefix(name, marker) || !strings.HasSuffix(name, suffix) {
		return nil
	}
	rawHex := strings.TrimSuffix(strings.TrimPrefix(name, marker), suffix)
	if len(rawHex) != sha256.Size*2 {
		return nil
	}
	digest, err := hex.DecodeString(rawHex)
	if err != nil || len(digest) != sha256.Size {
		return nil
	}
	return digest
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
