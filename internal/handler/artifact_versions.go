// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
)

func readDocumentArtifact(ctx context.Context, store *storage.Client, doc *generated.Document, key string, digest []byte, versionID pgtype.Text) ([]byte, error) {
	if store == nil || doc == nil || strings.TrimSpace(key) == "" || len(digest) != sha256.Size {
		return nil, errors.New("document artifact commitment is incomplete")
	}
	if versionID.Valid && strings.TrimSpace(versionID.String) != "" {
		return store.GetVerifiedVersion(ctx, key, versionID.String, digest)
	}
	if doc.EvidenceVersionPinsRequired {
		return nil, errors.New("document artifact is missing its required object VersionId")
	}
	body, _, err := store.ResolveVerifiedLegacy(ctx, key, digest)
	return body, err
}
