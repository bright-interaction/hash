// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
)

const signerClarifierTimeout = 35 * time.Second

// Phase 11 wires the three AI-backed features:
//
//   11.1  POST /sign/{token}/clarify        signer-side, magic-token authed
//   11.2  /api/v1/documents/{id}/proposals  sender-side, session authed
//   11.3  /api/v1/documents/{id}/bilingual  sender-side, session authed
//
// Each handler keeps the AI heavy lifting in internal/aiapps so the
// HTTP shell stays small + the audit + Shield-tokenized path is shared.

// POST /sign/{token}/clarify
//
// Body: { "block_id": "...", "selection_text": "...", "question": "...", "locale": "sv-SE" }
//
// Locale is optional; defaults to 'sv-SE'. We pull surrounding context
// from the signer's document view (the same block tree the rest of
// /sign/{token}/* serves), so the explanation is grounded in the
// clause's neighbours.
func (s *Server) handleSignerClarify(w http.ResponseWriter, r *http.Request) {
	if s.Clarifier == nil {
		writeError(w, http.StatusServiceUnavailable, "clarifier not configured")
		return
	}
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	noticeEvidence, ok := s.requireSignerNoticeAcknowledgement(w, r, rc)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	var in struct {
		BlockID       string `json:"block_id"`
		SelectionText string `json:"selection_text"`
		Question      string `json:"question"`
		Locale        string `json:"locale"`
	}
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.SelectionText == "" && in.BlockID == "" {
		writeError(w, http.StatusBadRequest, "selection_text or block_id required")
		return
	}

	// A SHARE row lock freezes both the document content and sent_at ceremony
	// epoch for the complete request-audit -> provider -> answer-audit sequence.
	// SHARE deliberately remains compatible with the KEY SHARE locks taken by
	// the separately committed events and AI-completion audit foreign keys; a
	// FOR UPDATE lock here would self-deadlock those durable writes.
	lockTx, err := s.Pool.Begin(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = lockTx.Rollback(rollbackCtx)
	}()
	lockedDoc, err := s.Queries.WithTx(lockTx).GetDocumentForShare(r.Context(), generated.GetDocumentForShareParams{
		ID: rc.Document.ID, OrgID: rc.Document.OrgID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "this document is no longer active")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if err := sign.ValidateLockedNoticeEvidence(rc, lockedDoc, noticeEvidence); err != nil {
		writeError(w, http.StatusPreconditionRequired, "acknowledge the current privacy notice before continuing")
		return
	}
	// Don't bill the LLM for documents that can no longer change. The status is
	// authoritative under the same lock that protects the notice epoch.
	switch lockedDoc.Status {
	case "sent", "in_progress", "changes_requested":
	default:
		writeError(w, http.StatusConflict, "this document is no longer active")
		return
	}

	// Persist the notice-bound processing request before sending any signer
	// content to the configured AI provider. Audit.Log uses its own short
	// transaction, so this record is committed durably while the SHARE lock
	// remains held. If the ledger is unavailable, fail closed without processing.
	requestPayload, err := bindSignerNoticeAuditPayload(noticeEvidence, map[string]any{
		"block_id": in.BlockID,
		"locale":   in.Locale,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if _, err := s.Audit.Log(r.Context(), audit.Entry{
		OrgID:       lockedDoc.OrgID,
		DocumentID:  &lockedDoc.ID,
		RecipientID: &rc.Recipient.ID,
		Kind:        "clarifier.requested",
		IP:          clientIP(r),
		UserAgent:   r.UserAgent(),
		Payload:     requestPayload,
	}); err != nil {
		writeInternalError(w, err)
		return
	}
	clauseText := in.SelectionText
	surrounding := ""
	if in.BlockID != "" {
		// Pull the block tree and use the neighbouring blocks as
		// grounding context. The selection text takes priority when
		// supplied (the signer may have highlighted a span shorter
		// than the whole block).
		tree, err := blocks.ParseTree(lockedDoc.BlocksJson)
		if err == nil {
			if blk, before, after := lookupBlockWithNeighbours(tree, in.BlockID); blk != nil {
				if clauseText == "" {
					clauseText = blk.Text
				}
				surrounding = before + "\n\n" + after
			}
		}
	}
	clarifyCtx, cancelClarify := context.WithTimeout(r.Context(), signerClarifierTimeout)
	defer cancelClarify()
	res, err := s.Clarifier.Clarify(clarifyCtx, aiapps.ClarifyInput{
		OrgID:              lockedDoc.OrgID,
		DocumentID:         lockedDoc.ID,
		Locale:             in.Locale,
		ClauseText:         clauseText,
		SurroundingContext: surrounding,
		Question:           in.Question,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	answerPayload, err := bindSignerNoticeAuditPayload(noticeEvidence, map[string]any{
		"block_id":      in.BlockID,
		"locale":        in.Locale,
		"shield_active": res.ShieldActive,
		"latency_ms":    res.LatencyMs,
		"input_tokens":  res.InputTokens,
		"output_tokens": res.OutputTokens,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if _, err := s.Audit.Log(r.Context(), audit.Entry{
		OrgID:       lockedDoc.OrgID,
		DocumentID:  &lockedDoc.ID,
		RecipientID: &rc.Recipient.ID,
		Kind:        "clarifier.answered",
		IP:          clientIP(r),
		UserAgent:   r.UserAgent(),
		Payload:     answerPayload,
	}); err != nil {
		writeInternalError(w, err)
		return
	}
	if err := lockTx.Commit(r.Context()); err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// lookupBlockWithNeighbours walks the top-level block list + finds the
// target by ID. Returns the block plus the rendered text of the
// previous and next blocks (joined for the "surrounding context" slot
// in the prompt).
func lookupBlockWithNeighbours(tree *blocks.Tree, id string) (*blocks.Block, string, string) {
	if tree == nil || len(tree.Blocks) == 0 {
		return nil, "", ""
	}
	idx := -1
	for i := range tree.Blocks {
		if tree.Blocks[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, "", ""
	}
	before, after := "", ""
	if idx > 0 {
		before = tree.Blocks[idx-1].Text
	}
	if idx+1 < len(tree.Blocks) {
		after = tree.Blocks[idx+1].Text
	}
	return &tree.Blocks[idx], before, after
}

// POST /api/v1/documents/{id}/proposals
//
// Body: { "block_id", "proposal_kind", "proposed_text", "rationale",
//
//	"ai_assisted": false, "parent_id": "..." }
func (s *Server) handleCreateProposal(w http.ResponseWriter, r *http.Request) {
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
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var in struct {
		BlockID      string `json:"block_id"`
		ProposalKind string `json:"proposal_kind"`
		ProposedText string `json:"proposed_text"`
		Rationale    string `json:"rationale"`
		AIAssisted   bool   `json:"ai_assisted"`
		ParentID     string `json:"parent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.BlockID == "" {
		writeError(w, http.StatusBadRequest, "block_id required")
		return
	}
	switch in.ProposalKind {
	case "edit", "reject", "counter", "block_lock":
	default:
		writeError(w, http.StatusBadRequest, "proposal_kind must be edit|reject|counter|block_lock")
		return
	}
	parent := pgtype.UUID{}
	if in.ParentID != "" {
		id, err := uuid.Parse(in.ParentID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "parent_id must be a uuid")
			return
		}
		parent = pgtype.UUID{Bytes: id, Valid: true}
	}
	row, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (*generated.DocumentProposal, error) {
			return q.InsertProposal(r.Context(), generated.InsertProposalParams{
				DocumentID:   doc.ID,
				OrgID:        sess.OrgID,
				ProposedBy:   pgtype.UUID{Bytes: sess.UserID, Valid: true},
				BlockID:      in.BlockID,
				ProposalKind: in.ProposalKind,
				ProposedText: in.ProposedText,
				Rationale:    in.Rationale,
				DiffJson:     []byte("{}"),
				AiAssisted:   in.AIAssisted,
				ParentID:     parent,
			})
		},
		func(row *generated.DocumentProposal) audit.Entry {
			return audit.Entry{
				OrgID:       sess.OrgID,
				ActorUserID: &sess.UserID,
				DocumentID:  &doc.ID,
				Kind:        "negotiation.proposed",
				IP:          firstIPFromHeader(r),
				UserAgent:   r.UserAgent(),
				Payload: map[string]any{
					"proposal_id": row.ID.String(),
					"block_id":    in.BlockID,
					"kind":        in.ProposalKind,
					"ai_assisted": in.AIAssisted,
				},
			}
		},
	)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, proposalToDTO(row))
}

// GET /api/v1/documents/{id}/proposals
func (s *Server) handleListProposals(w http.ResponseWriter, r *http.Request) {
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
	rows, err := s.Queries.ListProposalsByDocument(r.Context(), generated.ListProposalsByDocumentParams{
		DocumentID: docID,
		Limit:      200,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, p := range rows {
		out = append(out, proposalToDTO(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"proposals": out, "count": len(out)})
}

// PATCH /api/v1/proposals/{id}/status
//
// Body: { "status": "accepted" | "rejected" | "superseded" }
func (s *Server) handleSetProposalStatus(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var in struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	switch in.Status {
	case "accepted", "rejected", "superseded", "pending":
	default:
		writeError(w, http.StatusBadRequest, "status must be accepted|rejected|superseded|pending")
		return
	}
	row, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
		func(q *generated.Queries) (*generated.DocumentProposal, error) {
			return q.SetProposalStatus(r.Context(), generated.SetProposalStatusParams{
				ID:     id,
				OrgID:  sess.OrgID,
				Status: in.Status,
			})
		},
		func(row *generated.DocumentProposal) audit.Entry {
			return audit.Entry{
				OrgID:       sess.OrgID,
				ActorUserID: &sess.UserID,
				DocumentID:  &row.DocumentID,
				Kind:        "negotiation.status_changed",
				IP:          firstIPFromHeader(r),
				UserAgent:   r.UserAgent(),
				Payload:     map[string]any{"proposal_id": id.String(), "status": in.Status},
			}
		},
	)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proposalToDTO(row))
}

// POST /api/v1/documents/{id}/proposals/suggest
//
// Body: { "block_id", "concern", "red_lines": ["..."] }
// Returns an AI-drafted counter without persisting; caller can then
// POST /proposals with ai_assisted=true to commit.
func (s *Server) handleSuggestCounter(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if s.Negotiator == nil {
		writeError(w, http.StatusServiceUnavailable, "negotiator not configured")
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
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	var in struct {
		BlockID  string   `json:"block_id"`
		Concern  string   `json:"concern"`
		RedLines []string `json:"red_lines"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	tree, err := blocks.ParseTree(doc.BlocksJson)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	block, _, _ := lookupBlockWithNeighbours(tree, in.BlockID)
	if block == nil {
		writeError(w, http.StatusNotFound, "block_id not in document tree")
		return
	}
	res, err := s.Negotiator.SuggestCounter(r.Context(), aiapps.CounterInput{
		OrgID:          sess.OrgID,
		DocumentID:     doc.ID,
		UserID:         &sess.UserID,
		OriginalClause: block.Text,
		Concern:        in.Concern,
		RedLines:       in.RedLines,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// POST /api/v1/documents/{id}/bilingual/equivalence
//
// Body: { "block_id" OR "clause_a"+"clause_b", "lang_a", "lang_b" }
func (s *Server) handleBilingualEquivalence(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if s.Bilingual == nil {
		writeError(w, http.StatusServiceUnavailable, "bilingual checker not configured")
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
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var in struct {
		LangA   string `json:"lang_a"`
		LangB   string `json:"lang_b"`
		ClauseA string `json:"clause_a"`
		ClauseB string `json:"clause_b"`
		BlockID string `json:"block_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.ClauseA == "" && in.BlockID != "" {
		tree, perr := blocks.ParseTree(doc.BlocksJson)
		if perr == nil {
			if blk, _, _ := lookupBlockWithNeighbours(tree, in.BlockID); blk != nil {
				in.ClauseA = blk.Text
			}
		}
	}
	if in.ClauseA == "" || in.ClauseB == "" {
		writeError(w, http.StatusBadRequest, "clause_a and clause_b required (or block_id resolving to clause_a)")
		return
	}
	res, err := s.Bilingual.Check(r.Context(), aiapps.EquivalenceInput{
		OrgID:      sess.OrgID,
		DocumentID: doc.ID,
		UserID:     &sess.UserID,
		LangA:      in.LangA,
		ClauseA:    in.ClauseA,
		LangB:      in.LangB,
		ClauseB:    in.ClauseB,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID:       sess.OrgID,
		ActorUserID: &sess.UserID,
		DocumentID:  &doc.ID,
		Kind:        "bilingual.checked",
		Payload: map[string]any{
			"equivalent":    res.Equivalent,
			"confidence":    res.Confidence,
			"shield_active": res.ShieldActive,
		},
	})
	writeJSON(w, http.StatusOK, res)
}

// PATCH /api/v1/documents/{id}/negotiation-enabled
//
// Body: { "enabled": true }
func (s *Server) handleSetNegotiationEnabled(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if err := s.Queries.SetDocumentNegotiationEnabled(r.Context(), generated.SetDocumentNegotiationEnabledParams{
		ID: docID, OrgID: sess.OrgID, NegotiationEnabled: in.Enabled,
	}); err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"negotiation_enabled": in.Enabled})
}

// PATCH /api/v1/documents/{id}/bilingual-target
//
// Body: { "lang": "en-GB" }
func (s *Server) handleSetBilingualTarget(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var in struct {
		Lang string `json:"lang"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if err := s.Queries.SetDocumentBilingualTarget(r.Context(), generated.SetDocumentBilingualTargetParams{
		ID: docID, OrgID: sess.OrgID, BilingualTargetLang: in.Lang,
	}); err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bilingual_target_lang": in.Lang})
}

// POST /api/v1/documents/{id}/risk-analysis
//
// Body: { "locale": "sv-SE", "sender_context": "B2B SaaS, EU customers, no auto-renewal" }
//
// Both fields are optional. Runs the risk_analyzer prompt against the
// document's current block tree (skipping signature placeholders and
// empty blocks). Findings are NOT persisted ,  callers re-run when the
// draft changes.
func (s *Server) handleRunRiskAnalysis(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if s.RiskAnalyzer == nil {
		writeError(w, http.StatusServiceUnavailable, "risk analyzer not configured")
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
	var in struct {
		Locale        string `json:"locale"`
		SenderContext string `json:"sender_context"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	tree, err := blocks.ParseTree(doc.BlocksJson)
	if err != nil {
		writeInternalErrorMsg(w, "parse blocks", err)
		return
	}
	res, err := s.RiskAnalyzer.Analyze(r.Context(), aiapps.AnalyzeInput{
		OrgID:         sess.OrgID,
		DocumentID:    doc.ID,
		UserID:        &sess.UserID,
		Locale:        in.Locale,
		Blocks:        tree.Blocks,
		SenderContext: in.SenderContext,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID:       sess.OrgID,
		ActorUserID: &sess.UserID,
		DocumentID:  &doc.ID,
		Kind:        "risk.analyzed",
		IP:          firstIPFromHeader(r),
		UserAgent:   r.UserAgent(),
		Payload: map[string]any{
			"findings_count": len(res.Findings),
			"high":           countSeverity(res.Findings, aiapps.SeverityHigh),
			"medium":         countSeverity(res.Findings, aiapps.SeverityMedium),
			"low":            countSeverity(res.Findings, aiapps.SeverityLow),
			"shield_active":  res.ShieldActive,
			"latency_ms":     res.LatencyMs,
		},
	})
	writeJSON(w, http.StatusOK, res)
}

func countSeverity(fs []aiapps.Finding, sev string) int {
	n := 0
	for _, f := range fs {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

func proposalToDTO(p *generated.DocumentProposal) map[string]any {
	out := map[string]any{
		"id":            p.ID.String(),
		"document_id":   p.DocumentID.String(),
		"org_id":        p.OrgID.String(),
		"block_id":      p.BlockID,
		"proposal_kind": p.ProposalKind,
		"proposed_text": p.ProposedText,
		"rationale":     p.Rationale,
		"status":        p.Status,
		"ai_assisted":   p.AiAssisted,
		"diff_json":     json.RawMessage(p.DiffJson),
		"created_at":    p.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		"updated_at":    p.UpdatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if p.ProposedBy.Valid {
		out["proposed_by"] = uuid.UUID(p.ProposedBy.Bytes).String()
	}
	if p.RecipientID.Valid {
		out["recipient_id"] = uuid.UUID(p.RecipientID.Bytes).String()
	}
	if p.ParentID.Valid {
		out["parent_id"] = uuid.UUID(p.ParentID.Bytes).String()
	}
	return out
}

// guard imports + helpers
var _ = strings.ToLower
