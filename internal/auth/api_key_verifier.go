// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// PgVerifier wires APIKeyVerifier to the sqlc Queries against Postgres.
// It first checks the org-wide api_keys table; on a miss it falls
// through to v1.1's document_agent_tokens table. The second path sets
// a non-nil docScopeID return so the middleware can inject the
// DocumentScopeKey into the request context.
type PgVerifier struct {
	Queries *generated.Queries
}

func (v *PgVerifier) LookupByPrefix(ctx context.Context, prefix string) (uuid.UUID, uuid.UUID, uuid.UUID, string, string, []byte, uuid.UUID, []string, error) {
	// New credentials carry a table namespace in their high-entropy prefix, so
	// one credential class cannot shadow the other. Legacy 8-hex prefixes still
	// use the historical API-key-first fallback until they are rotated.
	if credentialNamespace(prefix) == documentTokenNamespace {
		return v.lookupDocumentToken(ctx, prefix)
	}
	row, err := v.Queries.GetAPIKeyByPrefix(ctx, prefix)
	if err == nil {
		user, uerr := v.Queries.GetUser(ctx, row.UserID)
		if uerr != nil {
			return uuid.Nil, uuid.Nil, uuid.Nil, "", "", nil, uuid.Nil, nil, uerr
		}
		return row.ID, user.ID, user.OrgID, user.Role, user.Email, row.KeyHash, uuid.Nil, row.Scopes, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, uuid.Nil, "", "", nil, uuid.Nil, nil, err
	}

	if credentialNamespace(prefix) == apiKeyPrefixNamespace {
		return uuid.Nil, uuid.Nil, uuid.Nil, "", "", nil, uuid.Nil, nil, errors.New("api key not found")
	}
	return v.lookupDocumentToken(ctx, prefix)
}

func (v *PgVerifier) lookupDocumentToken(ctx context.Context, prefix string) (uuid.UUID, uuid.UUID, uuid.UUID, string, string, []byte, uuid.UUID, []string, error) {
	// v1.1 fallback: doc-scoped agent tokens. Rejected if expired,
	// revoked, or past max_uses; otherwise the row's creator becomes
	// the identity (so audit logs attribute the call to a human) and
	// the document_id is the scope.
	doc, err := v.Queries.GetDocAgentTokenByPrefix(ctx, prefix)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, uuid.Nil, uuid.Nil, "", "", nil, uuid.Nil, nil, errors.New("api key not found")
		}
		return uuid.Nil, uuid.Nil, uuid.Nil, "", "", nil, uuid.Nil, nil, err
	}
	if doc.RevokedAt.Valid {
		return uuid.Nil, uuid.Nil, uuid.Nil, "", "", nil, uuid.Nil, nil, errors.New("token revoked")
	}
	if doc.ExpiresAt.Valid && doc.ExpiresAt.Time.Before(time.Now()) {
		return uuid.Nil, uuid.Nil, uuid.Nil, "", "", nil, uuid.Nil, nil, errors.New("token expired")
	}
	if doc.MaxUses > 0 && doc.UsedCount >= doc.MaxUses {
		return uuid.Nil, uuid.Nil, uuid.Nil, "", "", nil, uuid.Nil, nil, errors.New("token usage cap exceeded")
	}
	// NB: the use-counter bump happens in Claim (post-secret-verify), NOT here.
	// LookupByPrefix runs before the constant-time hash check, so incrementing
	// used_count here let a prefix-only attacker (the prefix is non-secret)
	// exhaust a max_uses-capped token and forge last_used_at with garbage
	// secrets. Claim is called by the middleware only after ConstantTimeCompare.

	userID := uuid.Nil
	role := "doc-token"
	email := ""
	if doc.CreatedBy.Valid {
		if u, err := v.Queries.GetUser(ctx, uuid.UUID(doc.CreatedBy.Bytes)); err == nil {
			userID = u.ID
			role = u.Role
			email = u.Email
		}
	}
	return doc.ID, userID, doc.OrgID, role, email, doc.KeyHash, doc.DocumentID, doc.Scopes, nil
}

func (v *PgVerifier) Claim(ctx context.Context, id, docScopeID uuid.UUID) error {
	if docScopeID == uuid.Nil {
		// Org-wide API keys are not usage-capped. Keep last_used_at synchronous
		// so request completion has deterministic credential telemetry.
		_, err := v.Queries.ClaimAPIKeyUse(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("api key unavailable")
		}
		return err
	}
	_, err := v.Queries.ClaimDocAgentTokenUse(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("document token unavailable")
	}
	return err
}
