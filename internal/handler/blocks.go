package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/blocks"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/versions"
)

// Block CRUD endpoints. Same shape the MCP authoring tools call into;
// shared via mutateTree below so REST + MCP stay consistent.

type appendBlockInput struct {
	Block blocks.Block `json:"block"`
}

func (s *Server) handleAppendBlock(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in appendBlockInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	doc, err := s.mutateTree(r, u.OrgID, u.UserID, docID, "rest:append_block", func(t *blocks.Tree) error {
		t.Blocks = append(t.Blocks, in.Block)
		return blocks.Validate(t)
	})
	if err != nil {
		writeError(w, mapMutationStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

type updateBlockInput struct {
	Block blocks.Block `json:"block"`
}

func (s *Server) handleUpdateBlock(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	bid := chiURLParam(r, "bid")
	if bid == "" {
		writeError(w, http.StatusBadRequest, "block id required")
		return
	}
	var in updateBlockInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	doc, err := s.mutateTree(r, u.OrgID, u.UserID, docID, "rest:update_block", func(t *blocks.Tree) error {
		for i := range t.Blocks {
			if t.Blocks[i].ID == bid {
				in.Block.ID = bid
				t.Blocks[i] = in.Block
				return blocks.Validate(t)
			}
		}
		return errors.New("block not found")
	})
	if err != nil {
		writeError(w, mapMutationStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

func (s *Server) handleDeleteBlock(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	bid := chiURLParam(r, "bid")
	if bid == "" {
		writeError(w, http.StatusBadRequest, "block id required")
		return
	}
	doc, err := s.mutateTree(r, u.OrgID, u.UserID, docID, "rest:delete_block", func(t *blocks.Tree) error {
		filtered := make([]blocks.Block, 0, len(t.Blocks))
		removed := false
		for _, b := range t.Blocks {
			if b.ID == bid {
				removed = true
				continue
			}
			filtered = append(filtered, b)
		}
		if !removed {
			return errors.New("block not found")
		}
		t.Blocks = filtered
		return nil
	})
	if err != nil {
		writeError(w, mapMutationStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

type reorderBlocksInput struct {
	BlockIDs []string `json:"block_ids"`
}

func (s *Server) handleReorderBlocks(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in reorderBlocksInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	doc, err := s.mutateTree(r, u.OrgID, u.UserID, docID, "rest:reorder_blocks", func(t *blocks.Tree) error {
		if len(in.BlockIDs) != len(t.Blocks) {
			return errors.New("block_ids length must equal top-level block count")
		}
		byID := map[string]blocks.Block{}
		for _, b := range t.Blocks {
			byID[b.ID] = b
		}
		seen := map[string]bool{}
		out := make([]blocks.Block, 0, len(in.BlockIDs))
		for _, id := range in.BlockIDs {
			b, ok := byID[id]
			if !ok || seen[id] {
				return fmt.Errorf("unknown or duplicate block id: %s", id)
			}
			seen[id] = true
			out = append(out, b)
		}
		t.Blocks = out
		return nil
	})
	if err != nil {
		writeError(w, mapMutationStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

type importHTMLInput struct {
	HTML string `json:"html"`
}

func (s *Server) handleImportHTML(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in importHTMLInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tree := blocks.ParseHTML(in.HTML)
	doc, err := s.replaceTree(r, u.OrgID, u.UserID, docID, "rest:import_html", tree)
	if err != nil {
		writeError(w, mapMutationStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

type importMarkdownInput struct {
	Markdown string `json:"markdown"`
}

func (s *Server) handleImportMarkdown(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in importMarkdownInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tree := blocks.ParseMarkdown(in.Markdown)
	doc, err := s.replaceTree(r, u.OrgID, u.UserID, docID, "rest:import_markdown", tree)
	if err != nil {
		writeError(w, mapMutationStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

func (s *Server) handlePreviewHTML(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	doc, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if doc.SourceKind != "blocks" {
		writeError(w, http.StatusBadRequest, "preview is only for blocks-source documents")
		return
	}
	tree, err := blocks.ParseTree(doc.BlocksJson)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stored blocks invalid: "+err.Error())
		return
	}
	vars, _, err := s.resolveVariables(r.Context(), doc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "resolve vars: "+err.Error())
		return
	}
	body := blocks.RenderHTML(tree, vars)
	brand, _ := s.resolveBrandingForDoc(r.Context(), doc)
	html := brand.CSSVariables() + body
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

// mutateTree loads the doc, applies fn to its block tree, persists, and
// audits. Used by REST and MCP both so the rules stay in one place.
func (s *Server) mutateTree(r *http.Request, orgID, userID uuid.UUID, docID uuid.UUID, toolName string, fn func(*blocks.Tree) error) (*generated.Document, error) {
	existing, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	if existing.Status != "draft" || existing.SourceKind != "blocks" {
		return nil, errors.New("document not editable (must be draft + blocks-source)")
	}
	tree, err := blocks.ParseTree(existing.BlocksJson)
	if err != nil {
		return nil, fmt.Errorf("existing blocks_json invalid: %w", err)
	}
	if err := fn(tree); err != nil {
		return nil, err
	}
	if err := blocks.Validate(tree); err != nil {
		return nil, fmt.Errorf("post-edit validation: %w", err)
	}
	raw, err := json.Marshal(tree)
	if err != nil {
		return nil, err
	}
	doc, err := s.Queries.UpdateDocumentBlocks(r.Context(), generated.UpdateDocumentBlocksParams{
		ID: docID, OrgID: orgID, BlocksJson: raw, VariablesJson: existing.VariablesJson,
	})
	if err != nil {
		return nil, err
	}
	s.snapshotAfterMutate(r.Context(), doc, &userID, versions.ViaHuman, toolName)
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: orgID, ActorUserID: &userID, DocumentID: &docID,
		Kind: audit.KindDocumentUpdated,
		IP:   firstIPFromHeader(r),
		UserAgent: r.UserAgent(),
		Payload: map[string]any{"via": "rest", "tool": toolName, "blocks": len(tree.Blocks)},
	})
	return doc, nil
}

// replaceTree replaces the entire block tree in one shot. Used by import
// endpoints.
func (s *Server) replaceTree(r *http.Request, orgID, userID uuid.UUID, docID uuid.UUID, toolName string, tree *blocks.Tree) (*generated.Document, error) {
	if err := blocks.Validate(tree); err != nil {
		return nil, fmt.Errorf("validation: %w", err)
	}
	raw, err := json.Marshal(tree)
	if err != nil {
		return nil, err
	}
	existing, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	if existing.Status != "draft" || existing.SourceKind != "blocks" {
		return nil, errors.New("document not editable (must be draft + blocks-source)")
	}
	doc, err := s.Queries.UpdateDocumentBlocks(r.Context(), generated.UpdateDocumentBlocksParams{
		ID: docID, OrgID: orgID, BlocksJson: raw, VariablesJson: existing.VariablesJson,
	})
	if err != nil {
		return nil, err
	}
	s.snapshotAfterMutate(r.Context(), doc, &userID, versions.ViaImport, toolName)
	_, _ = s.Audit.Log(r.Context(), audit.Entry{
		OrgID: orgID, ActorUserID: &userID, DocumentID: &docID,
		Kind:      audit.KindDocumentUpdated,
		IP:        firstIPFromHeader(r),
		UserAgent: r.UserAgent(),
		Payload:   map[string]any{"via": "rest", "tool": toolName, "blocks": len(tree.Blocks)},
	})
	return doc, nil
}

// snapshotAfterMutate persists a document_versions row reflecting the
// just-completed mutation. Called from mutateTree + replaceTree + restore so
// every state-changing edit produces exactly one new version. Best-effort:
// snapshot failures are logged but do not unwind the mutation; the audit log
// still captures the action.
func (s *Server) snapshotAfterMutate(ctx context.Context, doc *generated.Document, actor *uuid.UUID, via versions.Via, toolName string) {
	if s.Versions == nil || doc == nil {
		return
	}
	summary := toolName
	if summary == "" {
		summary = "edit"
	}
	_, err := s.Versions.Snapshot(ctx, versions.SnapshotInput{
		DocumentID:  doc.ID,
		OrgID:       doc.OrgID,
		Name:        doc.Name,
		SourceKind:  doc.SourceKind,
		BlocksJSON:  doc.BlocksJson,
		VariablesJS: doc.VariablesJson,
		CreatedBy:   actor,
		Via:         via,
		Summary:     summary,
	})
	if err != nil {
		// Don't fail the request: the snapshot is supplementary; the audit
		// log is the legal record. We surface failures via slog so the
		// telemetry pipeline can flag persistent breakages.
		slog.Default().Warn("versions: snapshot failed",
			"document_id", doc.ID, "error", err)
	}
}

// mapMutationStatus turns errors back into HTTP statuses.
func mapMutationStatus(err error) int {
	if errors.Is(err, errNotFound) {
		return http.StatusNotFound
	}
	msg := err.Error()
	switch {
	case msgContains(msg, "block not found"), msgContains(msg, "unknown or duplicate"), msgContains(msg, "block_ids length"):
		return http.StatusBadRequest
	case msgContains(msg, "not editable"), msgContains(msg, "not in draft"):
		return http.StatusConflict
	case msgContains(msg, "validation"):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func msgContains(s, substr string) bool {
	return len(s) >= len(substr) && (indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func chiURLParam(r *http.Request, name string) string {
	return chi.URLParam(r, name)
}

func firstIPFromHeader(r *http.Request) string {
	h := r.Header.Get("X-Forwarded-For")
	if h != "" {
		for i := 0; i < len(h); i++ {
			if h[i] == ',' {
				return strSpaceTrim(h[:i])
			}
		}
		return strSpaceTrim(h)
	}
	return r.RemoteAddr
}

func strSpaceTrim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
