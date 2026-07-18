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
	"math/big"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/db/generated"
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
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var in addFieldInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
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
	row, err := s.Queries.CreateField(r.Context(), generated.CreateFieldParams{
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
	if err != nil {
		writeInternalErrorMsg(w, "create field", err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
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
	})
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
	if err := s.Queries.DeleteFieldByID(r.Context(), generated.DeleteFieldByIDParams{
		ID: id, OrgID: sess.OrgID,
	}); err != nil {
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
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if len(in.Values) == 0 {
		writeError(w, http.StatusBadRequest, "values required")
		return
	}
	allowed, err := s.Queries.ListFieldsByRecipient(r.Context(), generated.ListFieldsByRecipientParams{
		DocumentID:  rc.Document.ID,
		RecipientID: pgtype.UUID{Bytes: rc.Recipient.ID, Valid: true},
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	allowedSet := map[string]*generated.DocumentField{}
	for _, f := range allowed {
		allowedSet[f.ID.String()] = f
	}
	updated := make([]map[string]any, 0, len(in.Values))
	for _, v := range in.Values {
		f, ok := allowedSet[v.FieldID]
		if !ok {
			writeError(w, http.StatusForbidden, "field_id not assigned to this recipient: "+v.FieldID)
			return
		}
		if f.Type == "signature" {
			writeError(w, http.StatusBadRequest, "signature fields are signed, not filled: "+v.FieldID)
			return
		}
		val := strings.TrimSpace(v.Value)
		if f.Required && val == "" {
			writeError(w, http.StatusBadRequest, "field is required: "+v.FieldID)
			return
		}
		row, err := s.Queries.UpdateFieldValue(r.Context(), generated.UpdateFieldValueParams{
			ID:         f.ID,
			DocumentID: rc.Document.ID,
			Value:      textOrNull(val),
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
		_, _ = s.Audit.Log(r.Context(), audit.Entry{
			OrgID:       rc.Document.OrgID,
			DocumentID:  &rc.Document.ID,
			RecipientID: &rc.Recipient.ID,
			Kind:        audit.KindDocumentFieldFill,
			IP:          clientIP(r),
			UserAgent:   r.UserAgent(),
			Payload: map[string]any{
				"field_id":   f.ID.String(),
				"type":       f.Type,
				"label":      f.Label.String,
				"value_len":  len(val),
				"value_hash": hashFieldValueForAudit(val),
			},
		})
		updated = append(updated, fieldToDTO(row))
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": updated, "count": len(updated)})
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
