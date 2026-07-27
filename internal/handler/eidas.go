// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
)

// Phase 9.2 eIDAS REST surface. CRUD over org_id-scoped routing rules,
// a "preview" endpoint that runs the engine against a hypothetical
// input so the rule-builder UI can show "this rule would trigger AES",
// a "seed Swedish defaults" button, and a per-document tier setter.

// ruleDTO is the wire shape for REST + MCP.
type ruleDTO struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Priority     int32           `json:"priority"`
	Predicate    json.RawMessage `json:"predicate_json"`
	RequiredTier string          `json:"required_tier"`
	Reason       string          `json:"reason"`
	Active       bool            `json:"active"`
	CreatedAt    string          `json:"created_at"`
	UpdatedAt    string          `json:"updated_at"`
}

func toRuleDTO(r *generated.EidasRoutingRule) ruleDTO {
	return ruleDTO{
		ID:           r.ID.String(),
		Name:         r.Name,
		Priority:     r.Priority,
		Predicate:    r.PredicateJson,
		RequiredTier: r.RequiredTier,
		Reason:       r.Reason,
		Active:       r.Active,
		CreatedAt:    r.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		UpdatedAt:    r.UpdatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}

// GET /api/v1/eidas-rules
func (s *Server) handleListEIDASRules(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	rules, err := s.Queries.ListEIDASRules(r.Context(), sess.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]ruleDTO, 0, len(rules))
	for _, r := range rules {
		out = append(out, toRuleDTO(r))
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out, "count": len(out)})
}

// POST /api/v1/eidas-rules
//
// Body: { name, priority, predicate_json, required_tier, reason, active }
func (s *Server) handleCreateEIDASRule(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	var in struct {
		Name         string          `json:"name"`
		Priority     int32           `json:"priority"`
		Predicate    json.RawMessage `json:"predicate_json"`
		RequiredTier string          `json:"required_tier"`
		Reason       string          `json:"reason"`
		Active       *bool           `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if !eidas.Tier(in.RequiredTier).Valid() {
		writeError(w, http.StatusBadRequest, "required_tier must be SES, AES, or QES")
		return
	}
	if len(in.Predicate) == 0 {
		writeError(w, http.StatusBadRequest, "predicate_json required")
		return
	}
	active := true
	if in.Active != nil {
		active = *in.Active
	}
	row, err := s.Queries.InsertEIDASRule(r.Context(), generated.InsertEIDASRuleParams{
		OrgID:         sess.OrgID,
		Name:          in.Name,
		Priority:      in.Priority,
		PredicateJson: in.Predicate,
		RequiredTier:  in.RequiredTier,
		Reason:        in.Reason,
		Active:        active,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: sess.OrgID, ActorUserID: &sess.UserID,
		Kind:    audit.KindDocumentUpdated,
		Payload: map[string]any{"via": "rest", "tool": "create_eidas_rule", "rule_id": row.ID.String()},
	})
	writeJSON(w, http.StatusCreated, toRuleDTO(row))
}

// PATCH /api/v1/eidas-rules/{id}
func (s *Server) handleUpdateEIDASRule(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := s.Queries.GetEIDASRule(r.Context(), generated.GetEIDASRuleParams{ID: id, OrgID: sess.OrgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	var in struct {
		Name         *string          `json:"name"`
		Priority     *int32           `json:"priority"`
		Predicate    *json.RawMessage `json:"predicate_json"`
		RequiredTier *string          `json:"required_tier"`
		Reason       *string          `json:"reason"`
		Active       *bool            `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	name := existing.Name
	if in.Name != nil {
		name = *in.Name
	}
	priority := existing.Priority
	if in.Priority != nil {
		priority = *in.Priority
	}
	predicate := existing.PredicateJson
	if in.Predicate != nil && len(*in.Predicate) > 0 {
		predicate = *in.Predicate
	}
	tier := existing.RequiredTier
	if in.RequiredTier != nil {
		if !eidas.Tier(*in.RequiredTier).Valid() {
			writeError(w, http.StatusBadRequest, "required_tier must be SES, AES, or QES")
			return
		}
		tier = *in.RequiredTier
	}
	reason := existing.Reason
	if in.Reason != nil {
		reason = *in.Reason
	}
	active := existing.Active
	if in.Active != nil {
		active = *in.Active
	}
	row, err := s.Queries.UpdateEIDASRule(r.Context(), generated.UpdateEIDASRuleParams{
		ID:            id,
		OrgID:         sess.OrgID,
		Name:          name,
		Priority:      priority,
		PredicateJson: predicate,
		RequiredTier:  tier,
		Reason:        reason,
		Active:        active,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: sess.OrgID, ActorUserID: &sess.UserID,
		Kind:    audit.KindDocumentUpdated,
		Payload: map[string]any{"via": "rest", "tool": "update_eidas_rule", "rule_id": id.String()},
	})
	writeJSON(w, http.StatusOK, toRuleDTO(row))
}

// DELETE /api/v1/eidas-rules/{id}
func (s *Server) handleDeleteEIDASRule(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.Queries.DeleteEIDASRule(r.Context(), generated.DeleteEIDASRuleParams{ID: id, OrgID: sess.OrgID}); err != nil {
		writeInternalError(w, err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: sess.OrgID, ActorUserID: &sess.UserID,
		Kind:    audit.KindDocumentUpdated,
		Payload: map[string]any{"via": "rest", "tool": "delete_eidas_rule", "rule_id": id.String()},
	})
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/v1/eidas-rules/seed-sweden
//
// Idempotent. Adds the default Swedish rules an org should start with;
// existing rules with the same names are left untouched.
func (s *Server) handleSeedSwedishEIDASRules(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if err := s.EIDAS.SeedSwedishDefaults(r.Context(), sess.OrgID); err != nil {
		writeInternalError(w, err)
		return
	}
	rules, _ := s.Queries.ListEIDASRules(r.Context(), sess.OrgID)
	out := make([]ruleDTO, 0, len(rules))
	for _, r := range rules {
		out = append(out, toRuleDTO(r))
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out, "count": len(out)})
}

// POST /api/v1/eidas-rules/preview
//
// Body: { amount, country, document_type, variables, current_tier? }
// Runs the engine against the supplied hypothetical input. Useful for
// the rule-builder UI to show "if this contract had amount=200000, AES
// would be required" without committing a send.
func (s *Server) handlePreviewEIDASRules(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	var in struct {
		Amount       float64           `json:"amount"`
		Country      string            `json:"country"`
		DocumentType string            `json:"document_type"`
		Variables    map[string]string `json:"variables"`
		CurrentTier  string            `json:"current_tier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil && err.Error() != "EOF" {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.Variables == nil {
		in.Variables = map[string]string{}
	}
	decision, err := s.EIDAS.Evaluate(r.Context(), sess.OrgID, eidas.EvaluateInput{
		Amount:       in.Amount,
		Country:      in.Country,
		DocumentType: in.DocumentType,
		Variables:    in.Variables,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := map[string]any{
		"required_tier":   decision.RequiredTier,
		"matched_rules":   decision.MatchedRules,
		"evaluated_count": decision.EvaluatedCount,
	}
	if in.CurrentTier != "" {
		out["would_block"] = eidas.Tier(in.CurrentTier).Cmp(decision.RequiredTier) < 0
	}
	writeJSON(w, http.StatusOK, out)
}

// PATCH /api/v1/documents/{id}/routing-tier
//
// Body: { "routing_tier": "AES" }
func (s *Server) handleSetDocumentRoutingTier(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var in struct {
		RoutingTier string `json:"routing_tier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if !eidas.Tier(in.RoutingTier).Valid() {
		writeError(w, http.StatusBadRequest, "routing_tier must be SES, AES, or QES")
		return
	}
	if err := s.Queries.SetDocumentRoutingTier(r.Context(), generated.SetDocumentRoutingTierParams{
		ID: docID, OrgID: sess.OrgID, RoutingTier: in.RoutingTier,
	}); err != nil {
		writeInternalError(w, err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: sess.OrgID, ActorUserID: &sess.UserID, DocumentID: &docID,
		Kind:    audit.KindDocumentUpdated,
		Payload: map[string]any{"via": "rest", "tool": "set_routing_tier", "routing_tier": in.RoutingTier},
	})
	writeJSON(w, http.StatusOK, map[string]any{"routing_tier": in.RoutingTier})
}
