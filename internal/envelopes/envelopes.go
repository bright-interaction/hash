// Package envelopes implements Phase 8.6: PandaDoc-style multi-document
// bundles. An envelope is a special document (`is_envelope=true`) that
// contains other documents (`parent_envelope_id` pointing back). One
// signature ceremony covers every child, the audit cert serialises a
// manifest hashing each child's final PDF so the ed25519 signature
// transitively binds the whole instrument.
//
// What ships in 8.6:
//   - Identity columns + indexes (migration 00014).
//   - Engine CRUD: Create, Attach, Detach, Reorder, ListChildren.
//   - Manifest builder for the audit cert (per-child sha256 + position +
//     title; the cert HTML includes a manifest section when present).
//   - REST + MCP surface for agents and humans to manage envelopes.
//
// What is intentionally deferred to 8.6.1 (so the foundation can ship
// without a full sign-engine refactor):
//   - Envelope send flow that fans out signature fields across children
//     in one ceremony. v1 docs can still be sent solo today.
//   - Per-child signature-field targeting (signature_field carries a
//     target_document_id once 8.6.1 lands).
package envelopes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/db/generated"
)

// Engine owns envelope lifecycle. Keep one process-wide. Mirrors the
// versions.Engine pattern so handlers/MCP tools that need envelope
// awareness all go through a single point.
type Engine struct {
	Q *generated.Queries
}

// New builds an Engine bound to a sqlc Queries handle.
func New(q *generated.Queries) *Engine { return &Engine{Q: q} }

// PromoteToEnvelope flips is_envelope=true on an existing draft document
// so it can host children. The document must:
//
//   - belong to the caller's org,
//   - not already be a child (parent_envelope_id IS NULL),
//   - be blocks-source (we don't envelope PDF-source documents in v1).
//
// Returns the updated row; the caller can then call Attach for each
// child to fill the envelope.
func (e *Engine) PromoteToEnvelope(ctx context.Context, docID, orgID uuid.UUID) (*generated.Document, error) {
	row, err := e.Q.MarkAsEnvelope(ctx, generated.MarkAsEnvelopeParams{
		ID:    docID,
		OrgID: orgID,
	})
	if err != nil {
		return nil, fmt.Errorf("promote: %w", err)
	}
	return row, nil
}

// Attach links a child document to an envelope. Position defaults to
// the next slot after the highest existing position; pass <=0 for
// "append to end".
func (e *Engine) Attach(ctx context.Context, envelopeID, childID, orgID uuid.UUID, position int32) (*generated.Document, error) {
	if envelopeID == childID {
		return nil, errors.New("attach: envelope cannot contain itself")
	}
	// Confirm parent is actually an envelope + belongs to the org.
	parent, err := e.Q.GetDocument(ctx, generated.GetDocumentParams{ID: envelopeID, OrgID: orgID})
	if err != nil {
		return nil, fmt.Errorf("attach: get parent: %w", err)
	}
	if !parent.IsEnvelope {
		return nil, errors.New("attach: parent document is not an envelope (call promote first)")
	}
	if position <= 0 {
		maxPos, err := e.Q.MaxEnvelopePosition(ctx, pgUUIDValid(envelopeID))
		if err != nil {
			return nil, fmt.Errorf("attach: max position: %w", err)
		}
		position = maxPos + 1
	}
	row, err := e.Q.AttachToEnvelope(ctx, generated.AttachToEnvelopeParams{
		ID:               childID,
		ParentEnvelopeID: pgUUIDValid(envelopeID),
		EnvelopePosition: pgInt(position),
		OrgID:            orgID,
	})
	if err != nil {
		return nil, fmt.Errorf("attach: %w", err)
	}
	return row, nil
}

// Detach removes a child from its envelope. The child becomes a
// standalone document again. No-op if not currently attached.
func (e *Engine) Detach(ctx context.Context, childID, orgID uuid.UUID) (*generated.Document, error) {
	row, err := e.Q.DetachFromEnvelope(ctx, generated.DetachFromEnvelopeParams{
		ID:    childID,
		OrgID: orgID,
	})
	if err != nil {
		return nil, fmt.Errorf("detach: %w", err)
	}
	return row, nil
}

// Reorder applies an ordered list of child IDs to an envelope. Children
// not in the supplied order keep their existing position; children in
// the supplied list get positions 1, 2, 3, ... in input order. This
// covers both "sort the whole envelope" and "move one child up" by
// supplying the desired final order.
// orgID is REQUIRED and threaded into the query's tenant predicate so the reorder
// can only ever touch the caller's own envelope children, on every surface (the MCP
// tool reaches this with no prior org-scoped lookup).
func (e *Engine) Reorder(ctx context.Context, envelopeID, orgID uuid.UUID, orderedChildIDs []uuid.UUID) error {
	for i, childID := range orderedChildIDs {
		if err := e.Q.ReorderEnvelopeChild(ctx, generated.ReorderEnvelopeChildParams{
			ID:               childID,
			ParentEnvelopeID: pgUUIDValid(envelopeID),
			EnvelopePosition: pgInt(int32(i + 1)),
			OrgID:            orgID,
		}); err != nil {
			return fmt.Errorf("reorder child %d (%s): %w", i, childID, err)
		}
	}
	return nil
}

// Children returns the envelope's children in position order. Each
// child carries its own state (status, sent_at, etc.) which mirrors the
// envelope's after a send.
func (e *Engine) Children(ctx context.Context, envelopeID, orgID uuid.UUID) ([]*generated.Document, error) {
	return e.Q.ListEnvelopeChildren(ctx, generated.ListEnvelopeChildrenParams{
		ParentEnvelopeID: pgUUIDValid(envelopeID),
		OrgID:            orgID,
	})
}

// ManifestEntry describes one child document in the audit cert manifest.
// The cert HTML emits these as a table; the SHA-256 lets a third party
// (court reviewer, lawyer) verify each child PDF byte-for-byte.
type ManifestEntry struct {
	ChildID        string `json:"child_id"`
	Title          string `json:"title"`
	Position       int    `json:"position"`
	FinalPDFKey    string `json:"final_pdf_key,omitempty"`
	FinalPDFSHA256 string `json:"final_pdf_sha256,omitempty"`
	Status         string `json:"status"`
}

// Manifest is the JSON shape returned by the read endpoints and emitted
// inside the audit cert. The wrapper carries EnvelopeID + Hash so
// readers can verify the section wasn't tampered with even if the
// document HTML around it was edited (the hash is over canonical JSON
// of Entries).
type Manifest struct {
	SchemaVersion int             `json:"schema_version"`
	EnvelopeID    string          `json:"envelope_id"`
	EnvelopeTitle string          `json:"envelope_title"`
	Entries       []ManifestEntry `json:"entries"`
	ManifestSHA   string          `json:"manifest_sha256"`
}

// BuildManifest assembles the manifest for an envelope by listing its
// children and copying their final-PDF metadata. Children with no
// final_pdf_sha (not yet signed) emit the entry with empty SHA so the
// cert is still consistent during an in-progress envelope.
func (e *Engine) BuildManifest(ctx context.Context, envelope *generated.Document) (Manifest, error) {
	if envelope == nil {
		return Manifest{}, errors.New("manifest: nil envelope")
	}
	if !envelope.IsEnvelope {
		return Manifest{}, errors.New("manifest: document is not an envelope")
	}
	children, err := e.Children(ctx, envelope.ID, envelope.OrgID)
	if err != nil {
		return Manifest{}, err
	}
	entries := make([]ManifestEntry, 0, len(children))
	for i, c := range children {
		pos := i + 1
		if c.EnvelopePosition.Valid {
			pos = int(c.EnvelopePosition.Int32)
		}
		entry := ManifestEntry{
			ChildID:  c.ID.String(),
			Title:    c.Name,
			Position: pos,
			Status:   c.Status,
		}
		if c.FinalPdfKey.Valid {
			entry.FinalPDFKey = c.FinalPdfKey.String
		}
		if len(c.FinalPdfSha) > 0 {
			entry.FinalPDFSHA256 = hex.EncodeToString(c.FinalPdfSha)
		}
		entries = append(entries, entry)
	}
	man := Manifest{
		SchemaVersion: 1,
		EnvelopeID:    envelope.ID.String(),
		EnvelopeTitle: envelope.Name,
		Entries:       entries,
	}
	man.ManifestSHA = canonicalSHA(man.canonicalBytes())
	return man, nil
}

// canonicalBytes returns a stable byte representation of the manifest
// (entries only; the hash is over that representation). Avoids depending
// on map ordering or JSON whitespace by emitting positional, field-
// ordered key=value lines.
func (m Manifest) canonicalBytes() []byte {
	var sb strings.Builder
	sb.WriteString("envelope_id=" + m.EnvelopeID + "\n")
	sb.WriteString("envelope_title=" + m.EnvelopeTitle + "\n")
	for _, e := range m.Entries {
		fmt.Fprintf(&sb,
			"child_id=%s|title=%s|position=%d|status=%s|final_pdf_sha256=%s|final_pdf_key=%s\n",
			e.ChildID, e.Title, e.Position, e.Status, e.FinalPDFSHA256, e.FinalPDFKey)
	}
	return []byte(sb.String())
}

func canonicalSHA(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// HTMLSection returns the manifest section emitted inside an envelope's
// audit certificate. Designed to read clearly on the printed PDF: a
// table of child documents with their hashes + positions, plus the
// manifest's own hash so the ed25519 signature over the whole cert
// transitively binds the envelope.
func (m Manifest) HTMLSection() string {
	if len(m.Entries) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<section class="hash-envelope-manifest">`)
	sb.WriteString(`<h2>Envelope manifest</h2>`)
	fmt.Fprintf(&sb,
		`<p>This envelope binds %d documents as a single legal instrument. Each child PDF is hashed below; the manifest's SHA-256 forms part of the audit certificate so the ed25519 signature binds every child by reference.</p>`,
		len(m.Entries))
	sb.WriteString(`<table><thead><tr><th>#</th><th>Title</th><th>Status</th><th>SHA-256</th></tr></thead><tbody>`)
	for _, e := range m.Entries {
		sha := e.FinalPDFSHA256
		if sha == "" {
			sha = "(not yet signed)"
		}
		fmt.Fprintf(&sb,
			`<tr><td>%d</td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>`,
			e.Position,
			html.EscapeString(e.Title),
			html.EscapeString(e.Status),
			html.EscapeString(sha),
		)
	}
	sb.WriteString(`</tbody></table>`)
	fmt.Fprintf(&sb, `<p><strong>Manifest SHA-256:</strong> <code>%s</code></p>`, m.ManifestSHA)
	sb.WriteString(`</section>`)
	return sb.String()
}

// Helpers for pgtype conversions kept private; callers route through
// the Engine methods so they never touch pgtype directly.

func pgUUIDValid(u uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: u, Valid: true}
}

func pgInt(v int32) pgtype.Int4 {
	return pgtype.Int4{Int32: v, Valid: true}
}
