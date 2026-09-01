// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// Data Subject Rights (GDPR Articles 15-22).
//
// The privacy policy at /legal/privacy promised these without an
// endpoint to back them. Two surfaces now exist:
//
//   - Signer-facing: POST /sign/{token}/dsr lets a recipient raise a
//     request for their own data without an account. The magic-link
//     token authenticates them and scopes the request to their
//     recipient row + parent document.
//   - Sender-facing: /api/v1/dsr is session-authed and lets an org
//     admin list, track, deny, or directly raise requests (e.g. when a
//     DPO email arrives), run a recipient-row inventory export, and execute
//     the one automated fulfillment implemented here: targeted erasure.

// validDSRKinds is the closed set the schema CHECK accepts.
var validDSRKinds = map[string]bool{
	"access":        true,
	"rectification": true,
	"erasure":       true,
	"restriction":   true,
	"portability":   true,
	"objection":     true,
}

func isValidDSRKind(s string) bool { return validDSRKinds[s] }

func supportsAutomatedDSRFulfillment(kind string) bool { return kind == "erasure" }

// IsValidDSRStatusTransition reports whether a status change is permitted.
// Pure function so tests can lock the matrix down without a DB.
func IsValidDSRStatusTransition(from, to string) bool {
	allowed := map[string]map[string]bool{
		"open":        {"in_progress": true, "fulfilled": true, "denied": true, "withdrawn": true},
		"in_progress": {"fulfilled": true, "denied": true, "withdrawn": true},
		"fulfilled":   {},
		"denied":      {"in_progress": true}, // re-opens
		"withdrawn":   {"in_progress": true},
	}
	return allowed[from][to]
}

// AnonymizationMarker is the redaction sentinel stamped into recipients
// rows when an erasure request is fulfilled. Recognisable to operators
// without leaking the original PII; stable across rows so downstream
// joins still group correctly.
const AnonymizationMarker = "[redacted on data-subject erasure request]"

// AnonymizedEmail returns the redaction-marker email used for an
// erased recipient. Includes the request id so an auditor can trace
// the row back to the DSR record without needing the original email.
func AnonymizedEmail(requestID uuid.UUID) string {
	return fmt.Sprintf("redacted+%s@dsr.invalid", requestID.String())
}

type signerDSRInput struct {
	Kind string `json:"kind"`
	Note string `json:"note,omitempty"`
}

// POST /sign/{token}/dsr - signer raises a DSR against their own row.
func (s *Server) handleSignerDSR(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	var in signerDSRInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	in.Kind = strings.ToLower(strings.TrimSpace(in.Kind))
	if !isValidDSRKind(in.Kind) {
		writeError(w, http.StatusBadRequest, "kind must be one of access|rectification|erasure|restriction|portability|objection")
		return
	}
	payload := map[string]any{
		"source":       "signer-magic-link",
		"recipient_id": rc.Recipient.ID,
	}
	raw, _ := json.Marshal(payload)
	docID := rc.Document.ID
	recID := rc.Recipient.ID
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	q := s.Queries.WithTx(tx)
	lockedDoc, err := q.GetDocumentForUpdate(r.Context(), generated.GetDocumentForUpdateParams{
		ID: docID, OrgID: rc.Document.OrgID,
	})
	if err != nil {
		writeInternalErrorMsg(w, "lock document", err)
		return
	}
	if !documentAcceptsSignerPrivacyRequest(lockedDoc.Status) {
		writeError(w, http.StatusConflict, "document is not accepting signer privacy requests")
		return
	}
	freshRecipient, err := q.GetRecipient(r.Context(), generated.GetRecipientParams{ID: recID, OrgID: lockedDoc.OrgID})
	if err != nil {
		writeInternalErrorMsg(w, "load recipient", err)
		return
	}
	if freshRecipient.DocumentID != lockedDoc.ID {
		writeError(w, http.StatusConflict, "recipient no longer belongs to this document")
		return
	}
	req, err := q.CreateDataSubjectRequest(r.Context(), generated.CreateDataSubjectRequestParams{
		OrgID:         rc.Document.OrgID,
		DocumentID:    uuidToPgUUID(&docID),
		RecipientID:   uuidToPgUUID(&recID),
		SubjectEmail:  freshRecipient.Email,
		SubjectName:   freshRecipient.Name,
		Kind:          in.Kind,
		RequestedVia:  "signer",
		RequestedNote: in.Note,
		PayloadJson:   raw,
	})
	if err != nil {
		writeInternalErrorMsg(w, "persist", err)
		return
	}
	pendingAudit, err := s.Audit.LogTx(r.Context(), tx, audit.Entry{
		OrgID:       rc.Document.OrgID,
		DocumentID:  &docID,
		RecipientID: &recID,
		Kind:        audit.KindDataSubjectRequested,
		IP:          clientIP(r),
		UserAgent:   r.UserAgent(),
		Payload: map[string]any{
			"request_id": req.ID,
			"kind":       in.Kind,
			"via":        "signer",
		},
	})
	if err != nil {
		writeInternalErrorMsg(w, "audit", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeInternalErrorMsg(w, "commit", err)
		return
	}
	s.Audit.Publish(pendingAudit)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"request_id": req.ID,
		"status":     req.Status,
		"due_at":     req.DueAt,
	})
}

// documentAcceptsSignerPrivacyRequest mirrors the ordinary magic-link read
// states. A changes-requested ceremony still renders the Article 13 notice and
// its DSR form, so exercising a data-subject right must remain available while
// contractual response actions are paused.
func documentAcceptsSignerPrivacyRequest(status string) bool {
	switch status {
	case "sent", "in_progress", "changes_requested":
		return true
	default:
		return false
	}
}

type senderDSRInput struct {
	Kind         string `json:"kind"`
	SubjectEmail string `json:"subject_email"`
	SubjectName  string `json:"subject_name,omitempty"`
	DocumentID   string `json:"document_id,omitempty"`
	RecipientID  string `json:"recipient_id,omitempty"`
	Note         string `json:"note,omitempty"`
}

// POST /api/v1/dsr - sender-side DSR creation (e.g. a DPO email).
func (s *Server) handleCreateSenderDSR(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	var in senderDSRInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	in.Kind = strings.ToLower(strings.TrimSpace(in.Kind))
	if !isValidDSRKind(in.Kind) {
		writeError(w, http.StatusBadRequest, "kind must be one of access|rectification|erasure|restriction|portability|objection")
		return
	}
	in.SubjectEmail = strings.TrimSpace(in.SubjectEmail)
	if in.SubjectEmail == "" {
		writeError(w, http.StatusBadRequest, "subject_email required")
		return
	}
	docID, err := parseOptionalDSRUUID(in.DocumentID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid document_id")
		return
	}
	recID, err := parseOptionalDSRUUID(in.RecipientID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid recipient_id")
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	q := s.Queries.WithTx(tx)

	// Validate any body-supplied recipient/document FK belongs to the caller's
	// org BEFORE persisting it. Without this an attacker could point a DSR at
	// another tenant's recipient and later drive it to fulfilled (erasure),
	// destroying that tenant's signer record. The DSR row carries the caller's
	// org_id, but the recipient_id must be validated independently because the
	// two org references can otherwise diverge.
	if recID != uuid.Nil {
		rec, err := q.GetRecipient(r.Context(), generated.GetRecipientParams{ID: recID, OrgID: u.OrgID})
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "recipient not found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "recipient lookup failed")
			return
		}
		if docID != uuid.Nil && rec.DocumentID != docID {
			writeError(w, http.StatusConflict, "recipient does not belong to document_id")
			return
		}
		if docID == uuid.Nil {
			docID = rec.DocumentID
		}
	}
	if docID != uuid.Nil {
		if _, err := q.GetDocumentForUpdate(r.Context(), generated.GetDocumentForUpdateParams{ID: docID, OrgID: u.OrgID}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "document not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "document lookup failed")
			return
		}
	}

	payload := map[string]any{"source": "sender", "raised_by": u.UserID}
	raw, _ := json.Marshal(payload)
	req, err := q.CreateDataSubjectRequest(r.Context(), generated.CreateDataSubjectRequestParams{
		OrgID:         u.OrgID,
		DocumentID:    uuidToPgUUID(nonZero(docID)),
		RecipientID:   uuidToPgUUID(nonZero(recID)),
		SubjectEmail:  in.SubjectEmail,
		SubjectName:   in.SubjectName,
		Kind:          in.Kind,
		RequestedVia:  "sender",
		RequestedNote: in.Note,
		PayloadJson:   raw,
	})
	if err != nil {
		writeInternalErrorMsg(w, "persist", err)
		return
	}
	pendingAudit, err := s.Audit.LogTx(r.Context(), tx, audit.Entry{
		OrgID:       u.OrgID,
		ActorUserID: &u.UserID,
		Kind:        audit.KindDataSubjectRequested,
		IP:          clientIP(r),
		Payload: map[string]any{
			"request_id": req.ID,
			"kind":       in.Kind,
			"via":        "sender",
		},
	})
	if err != nil {
		writeInternalErrorMsg(w, "audit", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeInternalErrorMsg(w, "commit", err)
		return
	}
	s.Audit.Publish(pendingAudit)
	writeJSON(w, http.StatusAccepted, req)
}

// GET /api/v1/dsr?status=
func (s *Server) handleListDSR(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	rows, err := s.Queries.ListDataSubjectRequestsByOrg(r.Context(), generated.ListDataSubjectRequestsByOrgParams{
		OrgID:   u.OrgID,
		Column2: status,
		Limit:   100,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": rows})
}

type dsrTransitionInput struct {
	Status         string `json:"status"`
	ResolutionNote string `json:"resolution_note,omitempty"`
}

// PATCH /api/v1/dsr/{id}
func (s *Server) handleTransitionDSR(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in dsrTransitionInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	in.Status = strings.ToLower(strings.TrimSpace(in.Status))
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	q := s.Queries.WithTx(tx)
	cur, err := q.GetDataSubjectRequestForUpdate(r.Context(), generated.GetDataSubjectRequestForUpdateParams{ID: id, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if !IsValidDSRStatusTransition(cur.Status, in.Status) {
		writeError(w, http.StatusConflict, fmt.Sprintf("invalid transition %s -> %s", cur.Status, in.Status))
		return
	}
	if in.Status == "fulfilled" && !supportsAutomatedDSRFulfillment(cur.Kind) {
		writeError(w, http.StatusConflict, "automated fulfillment is unavailable for this request kind; keep it in progress and complete the approved external procedure")
		return
	}
	pendingAudits := make([]audit.PendingEvent, 0, 2)
	// Erasure fulfillment is all-or-nothing with the status flip and audit
	// rows. A request without a linked recipient cannot truthfully be marked
	// fulfilled by this targeted workflow.
	if in.Status == "fulfilled" && cur.Kind == "erasure" {
		if !cur.RecipientID.Valid {
			writeError(w, http.StatusConflict, "erasure fulfillment requires a linked recipient")
			return
		}
		recipientID := uuid.UUID(cur.RecipientID.Bytes)
		recipient, err := q.GetRecipient(r.Context(), generated.GetRecipientParams{ID: recipientID, OrgID: u.OrgID})
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusConflict, "linked recipient not found in this org")
			return
		}
		if err != nil {
			writeInternalErrorMsg(w, "load linked recipient", err)
			return
		}
		if cur.DocumentID.Valid && recipient.DocumentID != uuid.UUID(cur.DocumentID.Bytes) {
			writeError(w, http.StatusConflict, "linked recipient does not belong to the linked document")
			return
		}
		lockedDoc, err := q.GetDocumentForUpdate(r.Context(), generated.GetDocumentForUpdateParams{
			ID: recipient.DocumentID, OrgID: u.OrgID,
		})
		if err != nil {
			writeInternalErrorMsg(w, "lock linked document", err)
			return
		}
		signatures, err := q.ListSignaturesByDocument(r.Context(), lockedDoc.ID)
		if err != nil {
			writeInternalErrorMsg(w, "load signatures", err)
			return
		}
		if !documentAllowsDestructiveErasure(lockedDoc, len(signatures) > 0) {
			writeError(w, http.StatusConflict, "linked document has an active or unsealed evidence ceremony")
			return
		}

		anonEmail := AnonymizedEmail(cur.ID)
		affected, anonErr := q.AnonymizeRecipient(r.Context(), generated.AnonymizeRecipientParams{
			ID:    cur.RecipientID.Bytes,
			Email: anonEmail,
			Name:  AnonymizationMarker,
			OrgID: u.OrgID,
		})
		// A zero-row count is a hard failure. The transaction rollback keeps
		// the request open and prevents a partial redaction from escaping.
		if anonErr != nil || affected == 0 {
			if anonErr != nil {
				writeInternalErrorMsg(w, "anonymize", anonErr)
			} else {
				writeError(w, http.StatusConflict, "anonymize: linked recipient not found in this org")
			}
			return
		}
		targetSignatureCount := int64(0)
		for _, signature := range signatures {
			if signature.RecipientID == recipientID {
				targetSignatureCount++
			}
		}
		scrubbed, err := q.AnonymizeSignaturesByRecipient(r.Context(), generated.AnonymizeSignaturesByRecipientParams{
			RecipientID: cur.RecipientID.Bytes,
			TypedName:   AnonymizationMarker,
			OrgID:       u.OrgID,
		})
		if err != nil {
			writeInternalErrorMsg(w, "anonymize signatures", err)
			return
		}
		if scrubbed != targetSignatureCount {
			writeError(w, http.StatusConflict, "signature anonymization did not cover the linked recipient evidence")
			return
		}
		redacted, err := q.RedactDSRSubjectIdentifiers(r.Context(), generated.RedactDSRSubjectIdentifiersParams{
			ID: id, OrgID: u.OrgID, SubjectEmail: anonEmail, SubjectName: AnonymizationMarker,
		})
		if err != nil {
			writeInternalErrorMsg(w, "redact request identifiers", err)
			return
		}
		if redacted != 1 {
			writeError(w, http.StatusConflict, "request identifiers were not redacted")
			return
		}
		pendingAudit, err := s.Audit.LogTx(r.Context(), tx, audit.Entry{
			OrgID:       u.OrgID,
			ActorUserID: &u.UserID,
			RecipientID: pgUUIDToPtr(cur.RecipientID),
			Kind:        audit.KindDataSubjectAnonymized,
			Payload: map[string]any{
				"request_id": cur.ID,
				"marker":     AnonymizationMarker,
			},
		})
		if err != nil {
			writeInternalErrorMsg(w, "audit anonymization", err)
			return
		}
		pendingAudits = append(pendingAudits, pendingAudit)
	}

	row, err := q.UpdateDataSubjectRequestStatus(r.Context(), generated.UpdateDataSubjectRequestStatusParams{
		ID:             id,
		OrgID:          u.OrgID,
		Status:         in.Status,
		ResolutionNote: in.ResolutionNote,
		FulfilledBy:    uuidToPgUUID(nonZero(u.UserID)),
		ExpectedStatus: cur.Status,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "request status changed concurrently")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}

	kind := audit.KindDataSubjectFulfilled
	if in.Status == "denied" {
		kind = audit.KindDataSubjectDenied
	}
	if in.Status == "fulfilled" || in.Status == "denied" {
		pendingAudit, err := s.Audit.LogTx(r.Context(), tx, audit.Entry{
			OrgID:       u.OrgID,
			ActorUserID: &u.UserID,
			Kind:        kind,
			Payload: map[string]any{
				"request_id":              row.ID,
				"resolution_note_present": strings.TrimSpace(in.ResolutionNote) != "",
			},
		})
		if err != nil {
			writeInternalErrorMsg(w, "audit transition", err)
			return
		}
		pendingAudits = append(pendingAudits, pendingAudit)
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeInternalErrorMsg(w, "commit", err)
		return
	}
	for _, pendingAudit := range pendingAudits {
		s.Audit.Publish(pendingAudit)
	}
	writeJSON(w, http.StatusOK, row)
}

// GET /api/v1/data-subject/export?email=
//
// Operator inventory of every recipient row matching the email in the calling
// org. It returns JSON metadata and object keys, not the referenced documents;
// it is therefore an input to, not a complete Article 15/20 response package.
func (s *Server) handleDSRExport(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	if email == "" {
		writeError(w, http.StatusBadRequest, "email query param required")
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	q := s.Queries.WithTx(tx)
	rows, err := q.ExportSubjectData(r.Context(), generated.ExportSubjectDataParams{
		OrgID: u.OrgID,
		Lower: email,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	pendingAudit, err := s.Audit.LogTx(r.Context(), tx, audit.Entry{
		OrgID:       u.OrgID,
		ActorUserID: &u.UserID,
		Kind:        audit.KindDataSubjectFulfilled,
		Payload: map[string]any{
			"action":    "export",
			"row_count": len(rows),
		},
	})
	if err != nil {
		writeInternalErrorMsg(w, "audit export", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeInternalErrorMsg(w, "commit", err)
		return
	}
	s.Audit.Publish(pendingAudit)
	writeJSON(w, http.StatusOK, map[string]any{
		"subject_email": email,
		"rows":          rows,
		"generated_at":  jsonNow(),
	})
}

// jsonNow returns the current time as RFC3339 in UTC. Centralised so we
// can swap an injectable clock in later.
func jsonNow() string { return time.Now().UTC().Format("2006-01-02T15:04:05Z07:00") }

// nonZero returns a *uuid.UUID when the value is not the zero uuid, nil
// otherwise. Saves a uuid.Nil check at every call site.
func nonZero(u uuid.UUID) *uuid.UUID {
	if u == uuid.Nil {
		return nil
	}
	return &u
}

func parseOptionalDSRUUID(raw string) (uuid.UUID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return uuid.Nil, nil
	}
	return uuid.Parse(raw)
}

// documentAllowsDestructiveErasure prevents mutable relational evidence from
// being scrubbed while it can still influence a final PDF/certificate. A
// completed ceremony is safe only when all retained-artifact references are
// populated; non-completed records are safe only in inactive states with no
// captured signatures at all.
func documentAllowsDestructiveErasure(doc *generated.Document, hasCapturedSignatures bool) bool {
	if doc == nil {
		return false
	}
	if doc.Status == "completed" {
		return doc.EvidenceVersionPinsRequired &&
			(!doc.PdfStorageKey.Valid || (len(doc.PdfSha256) == sha256.Size && validDocumentVersionID(doc.PdfStorageVersionID))) &&
			(!doc.RenderedPdfKey.Valid || (len(doc.RenderedPdfSha) == sha256.Size && validDocumentVersionID(doc.RenderedPdfVersionID))) &&
			doc.FinalPdfKey.Valid && strings.TrimSpace(doc.FinalPdfKey.String) != "" && len(doc.FinalPdfSha) == sha256.Size && validDocumentVersionID(doc.FinalPdfVersionID) &&
			doc.AuditCertKey.Valid && strings.TrimSpace(doc.AuditCertKey.String) != "" && len(doc.AuditCertSha256) == sha256.Size && validDocumentVersionID(doc.AuditCertVersionID) &&
			doc.AuditPayloadKey.Valid && strings.TrimSpace(doc.AuditPayloadKey.String) != "" && len(doc.AuditPayloadSha256) == sha256.Size &&
			validDocumentVersionID(doc.AuditPayloadVersionID) &&
			doc.AuditSignatureKey.Valid && strings.TrimSpace(doc.AuditSignatureKey.String) != "" && len(doc.AuditSignatureSha256) == sha256.Size &&
			validDocumentVersionID(doc.AuditSignatureVersionID)
	}
	if hasCapturedSignatures {
		return false
	}
	switch doc.Status {
	case "draft", "declined", "voided", "expired":
		return true
	default:
		return false
	}
}

func validDocumentVersionID(versionID pgtype.Text) bool {
	trimmed := strings.TrimSpace(versionID.String)
	return versionID.Valid && trimmed != "" && len(versionID.String) <= 1024 &&
		trimmed != "hash:unversioned-development"
}

func uuidToPgUUID(u *uuid.UUID) pgtype.UUID {
	if u == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *u, Valid: true}
}

func pgUUIDToPtr(p pgtype.UUID) *uuid.UUID {
	if !p.Valid {
		return nil
	}
	u := uuid.UUID(p.Bytes)
	return &u
}
