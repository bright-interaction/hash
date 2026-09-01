// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
)

// registerEvidenceTools mounts the Phase 10.2 evidence-bundle surface
// for agents. Two tools: get_evidence_manifest (cheap preview) +
// export_evidence_package (full PDF bundle, base64-encoded so it fits
// the JSON-RPC response shape).
func registerEvidenceTools(s *Server, d Deps) {
	// download_final_pdf + download_audit_cert: the executed document and its
	// standalone audit certificate, base64-encoded. UNGATED (like the REST
	// /final-pdf + /audit-cert routes) so an agent on ANY plan can complete the
	// lifecycle and hand off the signed contract without a REST/UI fallback. The
	// paid evidence_bundle gate stays reserved for the verifiable package only.
	if d.Storage != nil {
		downloadTool := func(name, desc, notReady string, key func(*generated.Document) (string, bool)) ToolDef {
			return ToolDef{
				Name:        name,
				Description: desc,
				InputSchema: schemaObject(map[string]any{
					"document_id": stringSchema("document uuid (must be completed)"),
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
					objKey, ok := key(doc)
					if !ok {
						return nil, errors.New(notReady)
					}
					expected, err := evidenceArtifactDigest(doc, objKey)
					if err != nil {
						return nil, err
					}
					versionID, pinned, err := evidenceArtifactVersion(doc, objKey)
					if err != nil {
						return nil, err
					}
					var body []byte
					if pinned {
						body, err = d.Storage.GetVerifiedVersion(r.Context(), objKey, versionID, expected)
					} else {
						body, _, err = d.Storage.ResolveVerifiedLegacy(r.Context(), objKey, expected)
					}
					if err != nil {
						return nil, err
					}
					return map[string]any{
						"document_id":   id.String(),
						"document_name": doc.Name,
						"pdf_base64":    base64.StdEncoding.EncodeToString(body),
						"size_bytes":    len(body),
					}, nil
				},
			}
		}
		s.RegisterTool(downloadTool(
			"download_final_pdf",
			"Download the executed (signed) final PDF for a completed document, base64-encoded. This is the deliverable to hand off the signed contract; available on ANY plan (unlike the cryptographically verifiable evidence bundle).",
			"final pdf not yet rendered - document is not completed",
			func(dc *generated.Document) (string, bool) { return dc.FinalPdfKey.String, dc.FinalPdfKey.Valid },
		))
		s.RegisterTool(downloadTool(
			"download_audit_cert",
			"Download the standalone ed25519 audit-certificate PDF for a completed document, base64-encoded. The tamper-evidence certificate; available on ANY plan.",
			"audit certificate not yet rendered - document is not completed",
			func(dc *generated.Document) (string, bool) { return dc.AuditCertKey.String, dc.AuditCertKey.Valid },
		))
	}

	if d.Evidence == nil {
		return
	}

	s.RegisterTool(ToolDef{
		Name:        "get_evidence_manifest",
		MinFeature:  "evidence_bundle", // paid-feature gate, mirroring the REST evidence-bundle download
		Description: "Return the signed evidence-bundle manifest for a completed top-level document or envelope: hashes of the exact final PDF, audit certificate, ceremony events, version history, and independent certificate/export keys. Documents containing unverified legacy QES records are blocked rather than relabeled as qualified signatures.",
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
				switch {
				case errors.Is(err, evidence.ErrEvidenceUnavailable):
					return nil, errors.New("evidence bundle only available for a completed top-level document or envelope")
				case errors.Is(err, evidence.ErrUnboundLegacyQES):
					return nil, errors.New("evidence manifest blocked: document contains unverified legacy QES material")
				}
				return nil, err
			}
			return res.Manifest, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "export_evidence_package",
		MinFeature:  "evidence_bundle", // paid-feature gate, mirroring the REST evidence-bundle download
		Description: "Build a cryptographically verifiable evidence PDF bundle for a completed top-level document or envelope and return it base64-encoded. Documents containing unverified legacy QES records are blocked rather than relabeled as qualified signatures. Sender-side tool only; evidentiary sufficiency is transaction-specific.",
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
				switch {
				case errors.Is(err, evidence.ErrEvidenceUnavailable):
					return nil, errors.New("evidence bundle only available for a completed top-level document or envelope")
				case errors.Is(err, evidence.ErrUnboundLegacyQES):
					return nil, errors.New("evidence export blocked: document contains unverified legacy QES material")
				}
				return nil, err
			}
			if d.Audit == nil {
				return nil, errors.New("evidence export audit logger is unavailable")
			}
			if _, err := d.Audit.Log(r.Context(), audit.Entry{
				OrgID:       u.OrgID,
				ActorUserID: &u.UserID,
				DocumentID:  &doc.ID,
				Kind:        audit.KindDocumentUpdated,
				Payload: map[string]any{
					"via":                               "mcp",
					"tool":                              "export_evidence_package",
					"opentimestamps_attachment_present": res.Manifest.OpenTimestamps != nil,
					"opentimestamps_verified":           false,
				},
			}); err != nil {
				return nil, errors.New("could not record evidence export")
			}
			return map[string]any{
				"filename":   res.Filename,
				"pdf_base64": base64.StdEncoding.EncodeToString(res.Bytes),
				"size_bytes": len(res.Bytes),
				"manifest":   res.Manifest,
			}, nil
		},
	})
}

func evidenceArtifactDigest(doc *generated.Document, key string) ([]byte, error) {
	if doc == nil {
		return nil, errors.New("document is required")
	}
	if doc.FinalPdfKey.Valid && key == doc.FinalPdfKey.String {
		if len(doc.FinalPdfSha) != sha256.Size {
			return nil, errors.New("final pdf has no valid committed SHA-256")
		}
		return doc.FinalPdfSha, nil
	}
	if doc.AuditCertKey.Valid && key == doc.AuditCertKey.String {
		if len(doc.AuditCertSha256) == sha256.Size {
			return doc.AuditCertSha256, nil
		}
		if doc.EvidenceVersionPinsRequired {
			return nil, errors.New("audit certificate has no valid committed SHA-256")
		}
		name := path.Base(key)
		if !strings.HasPrefix(name, "audit-") || !strings.HasSuffix(name, ".pdf") {
			return nil, errors.New("audit certificate is not content-addressed")
		}
		raw := strings.TrimSuffix(strings.TrimPrefix(name, "audit-"), ".pdf")
		if len(raw) != sha256.Size*2 {
			return nil, errors.New("audit certificate key has an invalid SHA-256")
		}
		digest, err := hex.DecodeString(raw)
		if err != nil {
			return nil, errors.New("audit certificate key has an invalid SHA-256")
		}
		return digest, nil
	}
	return nil, errors.New("storage key is not a committed document artifact")
}

func evidenceArtifactVersion(doc *generated.Document, key string) (string, bool, error) {
	if doc == nil {
		return "", false, errors.New("document is required")
	}
	var versionID string
	var valid bool
	switch {
	case doc.FinalPdfKey.Valid && key == doc.FinalPdfKey.String:
		versionID, valid = doc.FinalPdfVersionID.String, doc.FinalPdfVersionID.Valid
	case doc.AuditCertKey.Valid && key == doc.AuditCertKey.String:
		versionID, valid = doc.AuditCertVersionID.String, doc.AuditCertVersionID.Valid
	default:
		return "", false, errors.New("storage key is not a committed document artifact")
	}
	if valid && strings.TrimSpace(versionID) != "" {
		return versionID, true, nil
	}
	if doc.EvidenceVersionPinsRequired {
		return "", false, errors.New("document artifact is missing its required object VersionId")
	}
	return "", false, nil
}
