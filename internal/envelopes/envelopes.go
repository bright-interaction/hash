// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package envelopes implements Phase 8.6: PandaDoc-style multi-document
// bundles. An envelope is a special document (`is_envelope=true`) that
// contains other documents (`parent_envelope_id` pointing back). One
// signature ceremony covers every child. The audit certificate serialises a
// manifest hashing each child's frozen content snapshot so the ed25519
// signature transitively binds the whole instrument without making the
// impossible claim that a final PDF can contain its own SHA-256.
//
// What ships in 8.6:
//   - Identity columns + indexes (migration 00014).
//   - Engine CRUD: Create, Attach, Detach, Reorder, ListChildren.
//   - Manifest builder for the audit cert (per-child frozen-content SHA-256 +
//     position + title; the cert HTML includes the signed section).
//   - REST + MCP surface for agents and humans to manage envelopes.
//   - Draft-only, parent-locked topology plus one send/sign/finalize ceremony
//     that freezes and renders every child as a single immutable instrument.
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

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
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
//   - still be in draft state,
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

// Detach removes a draft child from its draft envelope. The child becomes a
// standalone document again. A missing attachment or a topology that was
// locked by send returns an error.
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
		rows, err := e.Q.ReorderEnvelopeChild(ctx, generated.ReorderEnvelopeChildParams{
			ID:               childID,
			ParentEnvelopeID: pgUUIDValid(envelopeID),
			EnvelopePosition: pgInt(int32(i + 1)),
			OrgID:            orgID,
		})
		if err != nil {
			return fmt.Errorf("reorder child %d (%s): %w", i, childID, err)
		}
		if rows != 1 {
			return fmt.Errorf("reorder child %d (%s): child is not in this draft envelope", i, childID)
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
// ContentSnapshotSHA256 commits to the exact persisted block tree + frozen
// variables that produce the child body. It deliberately is not named or
// described as a final-PDF hash: envelope children share the combined final
// artifact containing this certificate, so such a hash would be circular.
type ManifestEntry struct {
	ChildID               string `json:"child_id"`
	Title                 string `json:"title"`
	Position              int    `json:"position"`
	ContentSnapshotSHA256 string `json:"content_snapshot_sha256"`
	Status                string `json:"status"`
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

// BuildManifest assembles a recomputable manifest from the currently persisted
// envelope children. For a completed envelope this must equal the terminal
// manifest signed into the audit certificate: send freezes child content,
// topology is locked outside draft, and completion changes only child status.
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
	return buildManifest(envelope, children, false)
}

// BuildTerminalManifest constructs the exact manifest signed while an envelope
// finalizes. The family-wide finalization claim has already moved every child
// to finalizing, so no child-addressed lifecycle event can enter after the
// completion high-water snapshot. Status is deterministically projected to the
// completed state written in the terminal transaction. The snapshot digest
// itself is calculated solely from already-frozen persisted child content.
func BuildTerminalManifest(envelope *generated.Document, children []*generated.Document) (Manifest, error) {
	if envelope == nil {
		return Manifest{}, errors.New("manifest: nil envelope")
	}
	for i, child := range children {
		if child == nil {
			return Manifest{}, fmt.Errorf("manifest: child %d is nil", i+1)
		}
		if !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != envelope.ID {
			return Manifest{}, fmt.Errorf("manifest: child %s is not attached to envelope", child.ID)
		}
		if child.IsEnvelope {
			return Manifest{}, fmt.Errorf("manifest: child %s is itself an envelope", child.ID)
		}
		if child.Status != "finalizing" {
			return Manifest{}, fmt.Errorf("manifest: child %s is not frozen for finalization", child.ID)
		}
	}
	return buildManifest(envelope, children, true)
}

func buildManifest(envelope *generated.Document, children []*generated.Document, terminal bool) (Manifest, error) {
	if envelope == nil {
		return Manifest{}, errors.New("manifest: nil envelope")
	}
	if !envelope.IsEnvelope {
		return Manifest{}, errors.New("manifest: document is not an envelope")
	}
	if len(children) == 0 {
		return Manifest{}, errors.New("manifest: envelope has no children")
	}
	entries := make([]ManifestEntry, 0, len(children))
	for i, c := range children {
		if c == nil {
			return Manifest{}, fmt.Errorf("manifest: child %d is nil", i+1)
		}
		snapshotSHA, err := contentSnapshotSHA(c)
		if err != nil {
			return Manifest{}, fmt.Errorf("manifest: child %s: %w", c.ID, err)
		}
		pos := i + 1
		if c.EnvelopePosition.Valid {
			pos = int(c.EnvelopePosition.Int32)
		}
		status := c.Status
		if terminal {
			status = "completed"
		}
		entries = append(entries, ManifestEntry{
			ChildID:               c.ID.String(),
			Title:                 c.Name,
			Position:              pos,
			ContentSnapshotSHA256: snapshotSHA,
			Status:                status,
		})
	}
	man := Manifest{
		SchemaVersion: 2,
		EnvelopeID:    envelope.ID.String(),
		EnvelopeTitle: envelope.Name,
		Entries:       entries,
	}
	man.ManifestSHA = canonicalSHA(man.canonicalBytes())
	return man, nil
}

// contentSnapshotSHA is a domain-separated digest of the exact legal child
// content persisted at send time. Length-prefixing removes delimiter ambiguity;
// parsing first ensures malformed block JSON can never be certified.
func contentSnapshotSHA(child *generated.Document) (string, error) {
	if child == nil {
		return "", errors.New("nil child")
	}
	if child.SourceKind != "blocks" {
		return "", fmt.Errorf("unsupported source kind %q", child.SourceKind)
	}
	if _, err := blocks.ParseTree(child.BlocksJson); err != nil {
		return "", fmt.Errorf("parse blocks: %w", err)
	}
	h := sha256.New()
	h.Write([]byte("hash:envelope-child-content-snapshot:v1\x00"))
	fmt.Fprintf(h, "child_id=%s\nsource_kind=%s\nblocks_length=%d\n", child.ID, child.SourceKind, len(child.BlocksJson))
	h.Write(child.BlocksJson)
	fmt.Fprintf(h, "\nvariables_length=%d\n", len(child.VariablesJson))
	h.Write(child.VariablesJson)
	return hex.EncodeToString(h.Sum(nil)), nil
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
			"child_id=%s|title=%s|position=%d|status=%s|content_snapshot_sha256=%s\n",
			e.ChildID, e.Title, e.Position, e.Status, e.ContentSnapshotSHA256)
	}
	return []byte(sb.String())
}

func canonicalSHA(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// HTMLSection returns the manifest section emitted inside an envelope's
// audit certificate. Designed to read clearly on the printed PDF: a
// table of child documents with their frozen-content hashes + positions, plus the
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
		`<p>This envelope binds %d documents as a single legal instrument. Each SHA-256 below commits to the exact frozen block tree and resolved variables used to render that child's section. It is a content-snapshot hash, not a circular hash of the combined final PDF that contains this certificate. The manifest's SHA-256 forms part of the signed audit certificate.</p>`,
		len(m.Entries))
	sb.WriteString(`<table><thead><tr><th>#</th><th>Title</th><th>Status</th><th>Frozen content snapshot SHA-256</th></tr></thead><tbody>`)
	for _, e := range m.Entries {
		fmt.Fprintf(&sb,
			`<tr><td>%d</td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>`,
			e.Position,
			html.EscapeString(e.Title),
			html.EscapeString(e.Status),
			html.EscapeString(e.ContentSnapshotSHA256),
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
