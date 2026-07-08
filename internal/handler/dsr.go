package handler

import (
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

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/db/generated"
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
//     admin list, fulfill, deny, or directly raise requests (e.g.
//     when a DPO email arrives), plus run an Article 15+20 data
//     export for any subject email in the org.

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
	req, err := s.Queries.CreateDataSubjectRequest(r.Context(), generated.CreateDataSubjectRequestParams{
		OrgID:         rc.Document.OrgID,
		DocumentID:    uuidToPgUUID(&docID),
		RecipientID:   uuidToPgUUID(&recID),
		SubjectEmail:  rc.Recipient.Email,
		SubjectName:   rc.Recipient.Name,
		Kind:          in.Kind,
		RequestedVia:  "signer",
		RequestedNote: in.Note,
		PayloadJson:   raw,
	})
	if err != nil {
		writeInternalErrorMsg(w, "persist", err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
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
	writeJSON(w, http.StatusAccepted, map[string]any{
		"request_id": req.ID,
		"status":     req.Status,
		"due_at":     req.DueAt,
	})
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
	if in.SubjectEmail == "" {
		writeError(w, http.StatusBadRequest, "subject_email required")
		return
	}
	docID, _ := uuid.Parse(in.DocumentID)
	recID, _ := uuid.Parse(in.RecipientID)

	// Validate any body-supplied recipient/document FK belongs to the caller's
	// org BEFORE persisting it. Without this an attacker could point a DSR at
	// another tenant's recipient and later drive it to fulfilled (erasure),
	// destroying that tenant's signer record. The DSR row carries the caller's
	// org_id, but the recipient_id must be validated independently because the
	// two org references can otherwise diverge.
	if recID != uuid.Nil {
		rec, err := s.Queries.GetRecipient(r.Context(), generated.GetRecipientParams{ID: recID, OrgID: u.OrgID})
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "recipient not found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "recipient lookup failed")
			return
		}
		if docID == uuid.Nil {
			docID = rec.DocumentID
		}
	}
	if docID != uuid.Nil {
		if _, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID}); err != nil {
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
	req, err := s.Queries.CreateDataSubjectRequest(r.Context(), generated.CreateDataSubjectRequestParams{
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
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID:       u.OrgID,
		ActorUserID: &u.UserID,
		Kind:        audit.KindDataSubjectRequested,
		IP:          clientIP(r),
		Payload: map[string]any{
			"request_id":    req.ID,
			"kind":          in.Kind,
			"subject_email": in.SubjectEmail,
			"via":           "sender",
		},
	})
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
	cur, err := s.Queries.GetDataSubjectRequest(r.Context(), generated.GetDataSubjectRequestParams{ID: id, OrgID: u.OrgID})
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
	row, err := s.Queries.UpdateDataSubjectRequestStatus(r.Context(), generated.UpdateDataSubjectRequestStatusParams{
		ID:             id,
		OrgID:          u.OrgID,
		Status:         in.Status,
		ResolutionNote: in.ResolutionNote,
		FulfilledBy:    uuidToPgUUID(nonZero(u.UserID)),
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}

	// Erasure fulfillment: anonymize the recipients row scoped to the
	// request. Skipped when no recipient is linked (a sender-side
	// request without a doc context can't auto-anonymize; the sender
	// must run a targeted erasure separately).
	if in.Status == "fulfilled" && cur.Kind == "erasure" && cur.RecipientID.Valid {
		anonEmail := AnonymizedEmail(row.ID)
		affected, anonErr := s.Queries.AnonymizeRecipient(r.Context(), generated.AnonymizeRecipientParams{
			ID:    cur.RecipientID.Bytes,
			Email: anonEmail,
			Name:  AnonymizationMarker,
			OrgID: u.OrgID,
		})
		// Anonymization failure is a hard error: we don't want to claim
		// "fulfilled" when the PII is still on disk. A 0-row count means the
		// linked recipient does not belong to this org (a stale or
		// cross-tenant recipient_id) - treat it exactly like an error and
		// reverse the status flip so a poisoned DSR can never report
		// fulfilled without an actual redaction.
		if anonErr != nil || affected == 0 {
			_, _ = s.Queries.UpdateDataSubjectRequestStatus(r.Context(), generated.UpdateDataSubjectRequestStatusParams{
				ID:             id,
				OrgID:          u.OrgID,
				Status:         cur.Status,
				ResolutionNote: cur.ResolutionNote,
				FulfilledBy:    cur.FulfilledBy,
			})
			if anonErr != nil {
				writeInternalErrorMsg(w, "anonymize", anonErr)
			} else {
				writeError(w, http.StatusConflict, "anonymize: linked recipient not found in this org")
			}
			return
		}
		// M2: the recipient row is not the only PII store. The signatures row
		// independently holds the signer's typed legal name, IP and user-agent;
		// scrub them too. Non-fatal if the recipient never signed (0 rows).
		_, _ = s.Queries.AnonymizeSignaturesByRecipient(r.Context(), generated.AnonymizeSignaturesByRecipientParams{
			RecipientID: cur.RecipientID.Bytes,
			TypedName:   AnonymizationMarker,
			OrgID:       u.OrgID,
		})
		_, _ = s.Audit.Log(r.Context(), audit.Entry{
			OrgID:       u.OrgID,
			ActorUserID: &u.UserID,
			RecipientID: pgUUIDToPtr(cur.RecipientID),
			Kind:        audit.KindDataSubjectAnonymized,
			Payload: map[string]any{
				"request_id": row.ID,
				"marker":     AnonymizationMarker,
			},
		})
	}

	// L7: redact the erasure request's OWN subject_email/subject_name once
	// fulfilled, so the request row doesn't retain the identifiers it was asked
	// to erase. Runs for any erasure (even sender-side, no recipient link).
	if in.Status == "fulfilled" && cur.Kind == "erasure" {
		_ = s.Queries.RedactDSRSubjectIdentifiers(r.Context(), generated.RedactDSRSubjectIdentifiersParams{
			ID:           id,
			OrgID:        u.OrgID,
			SubjectEmail: AnonymizedEmail(row.ID),
			SubjectName:  AnonymizationMarker,
		})
	}

	kind := audit.KindDataSubjectFulfilled
	if in.Status == "denied" {
		kind = audit.KindDataSubjectDenied
	}
	if in.Status == "fulfilled" || in.Status == "denied" {
		_, _ = s.Audit.Log(r.Context(), audit.Entry{
			OrgID:       u.OrgID,
			ActorUserID: &u.UserID,
			Kind:        kind,
			Payload: map[string]any{
				"request_id":      row.ID,
				"resolution_note": in.ResolutionNote,
			},
		})
	}
	writeJSON(w, http.StatusOK, row)
}

// GET /api/v1/data-subject/export?email=
//
// Article 15 + 20 export of every recipient row matching the email in
// the calling org. Returns JSON; the sender attaches signed PDFs (the
// document_final_pdf_key fields) when responding to the data subject.
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
	rows, err := s.Queries.ExportSubjectData(r.Context(), generated.ExportSubjectDataParams{
		OrgID: u.OrgID,
		Lower: email,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID:       u.OrgID,
		ActorUserID: &u.UserID,
		Kind:        audit.KindDataSubjectFulfilled,
		Payload: map[string]any{
			"action":        "export",
			"subject_email": email,
			"row_count":     len(rows),
		},
	})
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
