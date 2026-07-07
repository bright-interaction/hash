// Package magictoken centralises the recipient magic-link TTL policy so the
// REST handlers, the MCP workflow tools, and the reminder worker all mint
// tokens with the same expiry. The TTL fix was previously applied per-surface
// (REST only), so MCP + worker minted tokens with a NULL expiry that fails
// open. This package is the single source of truth for that invariant.
package magictoken

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// DefaultTTL caps every freshly-minted recipient magic link. 30 days matches
// the reminder cadence (3 + 7 + 14 + 30 days). Tokens are additionally bounded
// by documents.expires_at when that is shorter.
const DefaultTTL = 30 * 24 * time.Hour

// Expiry returns the expiry timestamp for a freshly minted (or rotated)
// magic-link token: the lesser of the document's expires_at (when set) and
// now + DefaultTTL. A NULL doc-expiry collapses to now + DefaultTTL. A
// doc-expiry already in the past is returned as-is so a late mint produces a
// born-expired token rather than silently extending a frozen document.
func Expiry(docExpiresAt pgtype.Timestamptz, now time.Time) pgtype.Timestamptz {
	chosen := now.Add(DefaultTTL)
	if docExpiresAt.Valid && !docExpiresAt.Time.IsZero() && docExpiresAt.Time.Before(chosen) {
		chosen = docExpiresAt.Time
	}
	return pgtype.Timestamptz{Time: chosen, Valid: true}
}
