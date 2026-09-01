// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package handler ,  fields.go ships v1.2 fillable-field support beyond
// signatures. The document_fields schema (00004) already supports text,
// date, checkbox, dropdown, initial. This file adds:
//
//	,  sender REST + MCP to add/list/delete fields on a document
//	,  signer REST to fetch + submit field values via the magic-token surface
//	,  validation that required fields are filled before the sign step
//
// Field values land in `value` + `completed_at` columns and are surfaced
// via the existing audit timeline as `document.field_filled` events so
// the evidence bundle includes them automatically.
package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
)

// pctToNumeric encodes a 0..100 percent-of-page coordinate as a
// pgtype.Numeric with 4 fractional digits (basis-point precision).
// document_fields stores NUMERIC(7,4); rounding past the 4th decimal
// is acceptable for PDF stamp coordinates.
func pctToNumeric(f float64) pgtype.Numeric {
	scaled := int64(f * 10000)
	return pgtype.Numeric{Int: big.NewInt(scaled), Exp: -4, Valid: true}
}

// numericToFloat reverses pctToNumeric for JSON responses. Returns 0
// when invalid so the client never sees null in a coordinate slot.
func numericToFloat(n pgtype.Numeric) float64 {
	if !n.Valid || n.Int == nil {
		return 0
	}
	f, _ := new(big.Float).SetInt(n.Int).Float64()
	return f * pow10(int(n.Exp))
}

func pow10(e int) float64 {
	p := 1.0
	switch {
	case e >= 0:
		for i := 0; i < e; i++ {
			p *= 10
		}
	default:
		for i := 0; i < -e; i++ {
			p /= 10
		}
	}
	return p
}

// textOrNull returns an empty pgtype.Text when s is empty so we keep
// NULL semantics for optional columns.
func textOrNull(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

// sha256Hex hashes a value for audit logs so we record that the field
// was filled (and what hash to compare against on dispute) without
// putting PII in the events stream.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// fieldKindAllowed restricts the field types that a sender may add via
// the REST surface. The 'signature' + 'date_signed' + 'name_auto' kinds
// are managed by the sign engine itself; senders must not insert them
// by hand or the audit cert will diverge.
func fieldKindAllowed(kind string) bool {
	switch kind {
	case "text", "date", "checkbox", "dropdown", "initial":
		return true
	}
	return false
}

type addFieldInput struct {
	RecipientID string         `json:"recipient_id"`
	Type        string         `json:"type"`
	Page        int            `json:"page"`
	XPct        float64        `json:"x_pct"`
	YPct        float64        `json:"y_pct"`
	WPct        float64        `json:"w_pct"`
	HPct        float64        `json:"h_pct"`
	Required    *bool          `json:"required"`
	Label       string         `json:"label"`
	Options     map[string]any `json:"options"`
}

// POST /api/v1/documents/{id}/fields
//
// Sender adds a fillable field overlay (text/date/checkbox/dropdown/initial)
// to the document. Coordinates are page-percentage so the same field
// renders correctly across PDF page sizes. Recipient assignment is
// optional; nil means "any recipient".
func (s *Server) handleAddField(w http.ResponseWriter, r *http.Request) {
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
	if doc.Status != "draft" {
		writeError(w, http.StatusConflict, "document not editable (must be draft)")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var in addFieldInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	// PDF-source documents place their signature fields visually in the
	// designer (there is no block tree to carry them), so 'signature' is an
	// allowed kind there. Block-source docs derive signature fields from the
	// block tree and must not hand-insert them.
	if in.Type == "signature" {
		if doc.SourceKind != "pdf" {
			writeError(w, http.StatusBadRequest, "signature fields come from the block tree for block-source documents")
			return
		}
		if in.RecipientID == "" {
			writeError(w, http.StatusBadRequest, "signature fields must be assigned to a recipient")
			return
		}
	} else if !fieldKindAllowed(in.Type) {
		writeError(w, http.StatusBadRequest, "type must be text|date|checkbox|dropdown|initial")
		return
	}
	if in.Page < 1 {
		in.Page = 1
	}
	recipientID := pgtype.UUID{}
	if in.RecipientID != "" {
		id, err := uuid.Parse(in.RecipientID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "recipient_id must be a uuid")
			return
		}
		recipientID = pgtype.UUID{Bytes: id, Valid: true}
	}
	required := true
	if in.Required != nil {
		required = *in.Required
	}
	optionsJSON := []byte(`{}`)
	if len(in.Options) > 0 {
		raw, err := json.Marshal(in.Options)
		if err == nil {
			optionsJSON = raw
		}
	}
	row, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (*generated.DocumentField, error) {
			return q.CreateDraftField(r.Context(), generated.CreateDraftFieldParams{
				DocumentID:  docID,
				RecipientID: recipientID,
				Type:        in.Type,
				Page:        int32(in.Page),
				XPct:        pctToNumeric(in.XPct),
				YPct:        pctToNumeric(in.YPct),
				WPct:        pctToNumeric(in.WPct),
				HPct:        pctToNumeric(in.HPct),
				Required:    required,
				Label:       textOrNull(in.Label),
				OptionsJson: optionsJSON,
			})
		},
		func(row *generated.DocumentField) audit.Entry {
			return audit.Entry{
				OrgID:       sess.OrgID,
				ActorUserID: &sess.UserID,
				DocumentID:  &docID,
				Kind:        "document.field_added",
				Payload: map[string]any{
					"field_id": row.ID.String(),
					"type":     in.Type,
					"page":     in.Page,
					"required": required,
				},
			}
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "document not editable or recipient does not belong to document")
		return
	}
	if err != nil {
		writeInternalErrorMsg(w, "create field", err)
		return
	}
	writeJSON(w, http.StatusCreated, fieldToDTO(row))
}

// GET /api/v1/documents/{id}/fields
func (s *Server) handleListFields(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
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
	rows, err := s.Queries.ListFieldsByDocument(r.Context(), docID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, f := range rows {
		out = append(out, fieldToDTO(f))
	}
	writeJSON(w, http.StatusOK, map[string]any{"fields": out, "count": len(out)})
}

// DELETE /api/v1/fields/{id}
func (s *Server) handleDeleteField(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	ownerDoc, err := s.Queries.GetFieldOwnerDoc(r.Context(), generated.GetFieldOwnerDocParams{ID: id, OrgID: sess.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "field not found")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if _, ok := s.requireDraftDocument(w, r, ownerDoc, sess); !ok {
		return
	}
	if _, err := s.Queries.DeleteFieldByID(r.Context(), generated.DeleteFieldByIDParams{
		ID: id, OrgID: sess.OrgID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusConflict, "document not editable (must be draft)")
			return
		}
		writeInternalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /sign/{token}/fields
//
// Signer fetches the fillable fields scoped to their recipient row
// (plus any unassigned fields). Used by the signer page to render input
// widgets above the document body.
func (s *Server) handleSignerListFields(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	rows, err := s.Queries.ListFieldsByRecipient(r.Context(), generated.ListFieldsByRecipientParams{
		DocumentID:  rc.Document.ID,
		RecipientID: pgtype.UUID{Bytes: rc.Recipient.ID, Valid: true},
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, f := range rows {
		// Signature fields are included so the signer page can show "sign
		// here" at the right spot on a pdf-source document; they are filled
		// via /sign/{token}/sign, not the field-submit path (guarded below).
		out = append(out, fieldToDTO(f))
	}
	writeJSON(w, http.StatusOK, map[string]any{"fields": out, "count": len(out)})
}

type submitFieldValueInput struct {
	FieldID string `json:"field_id"`
	Value   string `json:"value"`
}

type submitFieldsInput struct {
	Values []submitFieldValueInput `json:"values"`
}

type preparedSignerFieldValue struct {
	field *generated.DocumentField
	value string
}

type signerFieldValidationError struct {
	status  int
	message string
}

const maxSignerFieldValueBytes = 4096

func validateSignerFieldValue(field *generated.DocumentField, value string) error {
	if field == nil {
		return errors.New("field is unavailable")
	}
	if len(value) > maxSignerFieldValueBytes || !utf8.ValidString(value) {
		return fmt.Errorf("must be valid UTF-8 and at most %d bytes", maxSignerFieldValueBytes)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("must not contain control characters")
		}
	}
	if value == "" {
		return nil
	}

	switch field.Type {
	case "text":
		return nil
	case "initial":
		if utf8.RuneCountInString(value) > 6 {
			return errors.New("must contain at most 6 characters")
		}
		return nil
	case "date":
		parsed, err := time.Parse("2006-01-02", value)
		if err != nil || parsed.Format("2006-01-02") != value {
			return errors.New("must use YYYY-MM-DD")
		}
		return nil
	case "checkbox":
		if value != "true" && value != "false" {
			return errors.New("must be true or false")
		}
		return nil
	case "dropdown":
		var options struct {
			Choices []string `json:"choices"`
		}
		if err := json.Unmarshal(field.OptionsJson, &options); err != nil {
			return errors.New("has invalid configured choices")
		}
		for _, choice := range options.Choices {
			if value == choice {
				return nil
			}
		}
		return errors.New("must match a configured choice")
	default:
		return errors.New("has unsupported field type")
	}
}

func prepareSignerFieldValues(allowed []*generated.DocumentField, values []submitFieldValueInput) ([]preparedSignerFieldValue, *signerFieldValidationError) {
	allowedSet := make(map[string]*generated.DocumentField, len(allowed))
	for _, field := range allowed {
		if field != nil {
			allowedSet[field.ID.String()] = field
		}
	}
	seen := make(map[string]struct{}, len(values))
	prepared := make([]preparedSignerFieldValue, 0, len(values))
	for _, input := range values {
		if _, duplicate := seen[input.FieldID]; duplicate {
			return nil, &signerFieldValidationError{status: http.StatusBadRequest, message: "duplicate field_id: " + input.FieldID}
		}
		seen[input.FieldID] = struct{}{}
		field, ok := allowedSet[input.FieldID]
		if !ok {
			return nil, &signerFieldValidationError{status: http.StatusForbidden, message: "field_id not assigned to this recipient: " + input.FieldID}
		}
		if field.Type == "signature" {
			return nil, &signerFieldValidationError{status: http.StatusBadRequest, message: "signature fields are signed, not filled: " + input.FieldID}
		}
		value := strings.TrimSpace(input.Value)
		if field.Required && value == "" {
			return nil, &signerFieldValidationError{status: http.StatusBadRequest, message: "field is required: " + input.FieldID}
		}
		if err := validateSignerFieldValue(field, value); err != nil {
			return nil, &signerFieldValidationError{status: http.StatusBadRequest, message: "invalid " + field.Type + " field value: " + err.Error()}
		}
		prepared = append(prepared, preparedSignerFieldValue{field: field, value: value})
	}
	return prepared, nil
}

// POST /sign/{token}/fields
//
// Signer submits one or more field values. The handler validates each
// field belongs to either this recipient or is unassigned, then updates
// `value` + `completed_at`. Emits document.field_filled for each value
// so the audit timeline reflects the submission.
func (s *Server) handleSignerSubmitFields(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	noticeEvidence, ok := s.requireSignerNoticeAcknowledgement(w, r, rc)
	if !ok {
		return
	}
	// Only an active document accepts field fills. Without this a recipient with a
	// still-live token could mutate field values (and fire a viewed/fill event) on a
	// voided/completed/declined/expired legal record. The query below re-checks the
	// status under the row so a concurrent void mid-submit can't slip through (TOCTOU).
	if rc.Document.Status != "sent" && rc.Document.Status != "in_progress" {
		writeError(w, http.StatusConflict, "document is not accepting field updates")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	var in submitFieldsInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if len(in.Values) == 0 {
		writeError(w, http.StatusBadRequest, "values required")
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	q := s.Queries.WithTx(tx)
	lockedDoc, err := q.GetDocumentForUpdate(r.Context(), generated.GetDocumentForUpdateParams{
		ID: rc.Document.ID, OrgID: rc.Document.OrgID,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if err := sign.ValidateLockedNoticeEvidence(rc, lockedDoc, noticeEvidence); err != nil {
		writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		return
	}
	if lockedDoc.Status != "sent" && lockedDoc.Status != "in_progress" {
		writeError(w, http.StatusConflict, "document is not accepting field updates")
		return
	}
	freshRecipient, err := q.GetRecipient(r.Context(), generated.GetRecipientParams{
		ID: rc.Recipient.ID, OrgID: rc.Document.OrgID,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if freshRecipient.DocumentID != lockedDoc.ID || !recipientCanFillFields(freshRecipient.Status) {
		writeError(w, http.StatusConflict, "recipient has already completed or declined this ceremony")
		return
	}
	allowed, err := q.ListFieldsByRecipient(r.Context(), generated.ListFieldsByRecipientParams{
		DocumentID:  rc.Document.ID,
		RecipientID: pgtype.UUID{Bytes: rc.Recipient.ID, Valid: true},
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	prepared, validationErr := prepareSignerFieldValues(allowed, in.Values)
	if validationErr != nil {
		writeError(w, validationErr.status, validationErr.message)
		return
	}
	updated := make([]map[string]any, 0, len(prepared))
	pendingAudits := make([]audit.PendingEvent, 0, len(prepared))
	for _, item := range prepared {
		row, err := q.UpdateFieldValue(r.Context(), generated.UpdateFieldValueParams{
			ID:          item.field.ID,
			DocumentID:  rc.Document.ID,
			Value:       textOrNull(item.value),
			RecipientID: pgtype.UUID{Bytes: rc.Recipient.ID, Valid: true},
		})
		if errors.Is(err, pgx.ErrNoRows) {
			// The document went terminal between the pre-check and this write (or the
			// field isn't on this doc): refuse rather than mutate a sealed record.
			writeError(w, http.StatusConflict, "document is not accepting field updates")
			return
		}
		if err != nil {
			writeInternalError(w, err)
			return
		}
		fieldAuditPayload, err := bindSignerNoticeAuditPayload(noticeEvidence, map[string]any{
			"field_id":   item.field.ID.String(),
			"type":       item.field.Type,
			"label":      item.field.Label.String,
			"value_len":  len(item.value),
			"value_hash": hashFieldValueForAudit(item.value),
		})
		if err != nil {
			writeInternalError(w, err)
			return
		}
		pendingAudit, err := s.Audit.LogTx(r.Context(), tx, audit.Entry{
			OrgID:       rc.Document.OrgID,
			DocumentID:  &rc.Document.ID,
			RecipientID: &rc.Recipient.ID,
			Kind:        audit.KindDocumentFieldFill,
			IP:          clientIP(r),
			UserAgent:   r.UserAgent(),
			Payload:     fieldAuditPayload,
		})
		if err != nil {
			writeInternalError(w, err)
			return
		}
		pendingAudits = append(pendingAudits, pendingAudit)
		updated = append(updated, fieldToDTO(row))
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeInternalError(w, err)
		return
	}
	for _, pending := range pendingAudits {
		s.Audit.Publish(pending)
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": updated, "count": len(updated)})
}

func recipientCanFillFields(status string) bool {
	switch status {
	case "pending", "sent", "viewed":
		return true
	default:
		return false
	}
}

// fieldToDTO renders one document_fields row for the JSON API. The
// `value` column is included so the sender + signer pages can show
// previously-submitted values; `completed_at` lets the UI badge a
// field as already-filled.
func fieldToDTO(f *generated.DocumentField) map[string]any {
	out := map[string]any{
		"id":          f.ID.String(),
		"document_id": f.DocumentID.String(),
		"type":        f.Type,
		"page":        f.Page,
		"x_pct":       numericToFloat(f.XPct),
		"y_pct":       numericToFloat(f.YPct),
		"w_pct":       numericToFloat(f.WPct),
		"h_pct":       numericToFloat(f.HPct),
		"required":    f.Required,
	}
	if f.RecipientID.Valid {
		out["recipient_id"] = uuid.UUID(f.RecipientID.Bytes).String()
	}
	if f.Label.Valid {
		out["label"] = f.Label.String
	}
	if f.Value.Valid {
		out["value"] = f.Value.String
	}
	if f.CompletedAt.Valid {
		out["completed_at"] = f.CompletedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	if len(f.OptionsJson) > 0 {
		out["options"] = json.RawMessage(f.OptionsJson)
	}
	return out
}

// audit log records the SHA-256 hash of the submitted value, never the
// value itself, so PII (names, addresses, free-text answers) doesn't
// leak into the audit trail. The full value lives in document_fields
// where org-scoped reads gate it.
func hashFieldValueForAudit(v string) string {
	if v == "" {
		return ""
	}
	return sha256Hex(v)
}
