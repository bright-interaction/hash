package mcp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/evidence"
)

// registerEvidenceTools mounts the Phase 10.2 evidence-bundle surface
// for agents. Two tools: get_evidence_manifest (cheap preview) +
// export_evidence_package (full PDF bundle, base64-encoded so it fits
// the JSON-RPC response shape).
func registerEvidenceTools(s *Server, d Deps) {
	if d.Evidence == nil {
		return
	}

	s.RegisterTool(ToolDef{
		Name:        "get_evidence_manifest",
		MinFeature:  "evidence_bundle", // paid-feature gate, mirroring the REST evidence-bundle download
		Description: "Return just the evidence-bundle manifest for a terminal document (completed/declined/voided/expired): SHA-256 hashes of the final PDF, audit cert, events feed, version history, public key. Cheap preview before the full bundle download.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
		}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			res, err := d.Evidence.Build(r.Context(), doc)
			if err != nil {
				if errors.Is(err, evidence.ErrNotTerminal) {
					return nil, errors.New("evidence bundle only available for terminal documents")
				}
				return nil, err
			}
			return res.Manifest, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "export_evidence_package",
		MinFeature:  "evidence_bundle", // paid-feature gate, mirroring the REST evidence-bundle download
		Description: "Build the court-ready evidence PDF bundle for a terminal document and return it base64-encoded. Contains the signed final PDF as the visible body + machine-readable attachments (manifest.json, events.json, versions.json, public-key.pem, optional cert.ots). Sender-side tool only.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
		}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("document not found")
			}
			if err != nil {
				return nil, err
			}
			res, err := d.Evidence.Build(r.Context(), doc)
			if err != nil {
				if errors.Is(err, evidence.ErrNotTerminal) {
					return nil, errors.New("evidence bundle only available for terminal documents")
				}
				return nil, err
			}
			_, _ = d.Audit.Log(r.Context(), audit.Entry{
				OrgID:       u.OrgID,
				ActorUserID: &u.UserID,
				DocumentID:  &doc.ID,
				Kind:        audit.KindDocumentUpdated,
				Payload: map[string]any{
					"via":               "mcp",
					"tool":              "export_evidence_package",
					"manifest_anchored": res.Manifest.OpenTimestamps != nil,
				},
			})
			return map[string]any{
				"filename":   res.Filename,
				"pdf_base64": base64.StdEncoding.EncodeToString(res.Bytes),
				"size_bytes": len(res.Bytes),
				"manifest":   res.Manifest,
			}, nil
		},
	})
}
