package mcp

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/db/generated"
)

// scopedDocLookup is the single doc-fetch primitive MCP tools should
// call. It enforces:
//
//  1. the v1.1 per-document agent-token scope (auth.EnforceDocScope),
//     so a scoped token cannot read documents other than its bound one;
//  2. the standard org-membership check via the existing
//     Queries.GetDocument OrgID parameter.
//
// Returns the document on success, a "document not found" error on
// pgx.ErrNoRows or scope mismatch, and the raw error for anything else.
//
// Tools that previously called d.Queries.GetDocument directly should
// migrate to this helper so the scope check lands once + everywhere.
func scopedDocLookup(ctx context.Context, q *generated.Queries, docID, orgID uuid.UUID) (*generated.Document, error) {
	if err := auth.EnforceDocScope(ctx, docID); err != nil {
		return nil, err
	}
	doc, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: docID, OrgID: orgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("document not found")
		}
		return nil, err
	}
	return doc, nil
}
