// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/magictoken"
)

// computeMagicTokenExpiry delegates to the shared magictoken.Expiry helper so
// the handler, the MCP tools, and the worker all compute the same TTL. Kept as
// a thin wrapper so the existing handler call sites (recipients.go) compile
// unchanged.
func computeMagicTokenExpiry(doc *generated.Document, now time.Time) pgtype.Timestamptz {
	var docExp pgtype.Timestamptz
	if doc != nil {
		docExp = doc.ExpiresAt
	}
	return magictoken.Expiry(docExp, now)
}
