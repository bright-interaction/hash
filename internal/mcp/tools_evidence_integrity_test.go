// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestEvidenceArtifactDigestFailsClosed(t *testing.T) {
	final := sha256.Sum256([]byte("final"))
	cert := sha256.Sum256([]byte("cert"))
	doc := &generated.Document{
		FinalPdfKey: pgtype.Text{String: "org/o/documents/d/final.pdf", Valid: true},
		FinalPdfSha: final[:],
		AuditCertKey: pgtype.Text{
			String: "org/o/documents/d/audit-" + hex.EncodeToString(cert[:]) + ".pdf", Valid: true,
		},
	}
	got, err := evidenceArtifactDigest(doc, doc.FinalPdfKey.String)
	if err != nil || string(got) != string(final[:]) {
		t.Fatalf("final digest = %x, %v", got, err)
	}
	got, err = evidenceArtifactDigest(doc, doc.AuditCertKey.String)
	if err != nil || string(got) != string(cert[:]) {
		t.Fatalf("certificate digest = %x, %v", got, err)
	}
	for _, key := range []string{
		"org/o/documents/d/audit.pdf",
		"org/o/documents/d/audit-not-a-digest.pdf",
		"org/o/documents/d/other.pdf",
	} {
		if _, err := evidenceArtifactDigest(doc, key); err == nil {
			t.Fatalf("uncommitted artifact key %q should fail closed", key)
		}
	}
}

func TestEvidenceArtifactVersionRequiresPinsForModernDocuments(t *testing.T) {
	doc := &generated.Document{
		FinalPdfKey:                 pgtype.Text{String: "org/o/documents/d/final.pdf", Valid: true},
		FinalPdfVersionID:           pgtype.Text{String: "final-version-1", Valid: true},
		AuditCertKey:                pgtype.Text{String: "org/o/documents/d/audit.pdf", Valid: true},
		EvidenceVersionPinsRequired: true,
	}
	versionID, pinned, err := evidenceArtifactVersion(doc, doc.FinalPdfKey.String)
	if err != nil || !pinned || versionID != "final-version-1" {
		t.Fatalf("final artifact version = %q, %t, %v", versionID, pinned, err)
	}
	if _, _, err := evidenceArtifactVersion(doc, doc.AuditCertKey.String); err == nil {
		t.Fatal("modern audit certificate without VersionId was accepted")
	}
	doc.EvidenceVersionPinsRequired = false
	versionID, pinned, err = evidenceArtifactVersion(doc, doc.AuditCertKey.String)
	if err != nil || pinned || versionID != "" {
		t.Fatalf("explicit legacy artifact version = %q, %t, %v", versionID, pinned, err)
	}
}
