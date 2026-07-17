package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/brightinteraction/hash/internal/db/generated"
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
	// NB: the use-counter bump happens in Touch (post-secret-verify), NOT here.
	// LookupByPrefix runs before the constant-time hash check, so incrementing
	// used_count here let a prefix-only attacker (the prefix is non-secret)
	// exhaust a max_uses-capped token and forge last_used_at with garbage
	// secrets. Touch is called by the middleware only after ConstantTimeCompare.

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

func (v *PgVerifier) Touch(ctx context.Context, id uuid.UUID) error {
	// The id belongs to exactly one of the two token tables. Touch both: the
	// non-matching UPDATE affects zero rows and is a no-op. We cannot short-
	// circuit on the api_keys touch succeeding, because TouchAPIKey is :exec and
	// returns nil even when it matched zero rows (a doc-token id), which would
	// leave document_agent_tokens.used_count / last_used_at never updated.
	errA := v.Queries.TouchAPIKey(ctx, id)
	errB := v.Queries.TouchDocAgentToken(ctx, id)
	if errA != nil {
		return errA
	}
	return errB
}
