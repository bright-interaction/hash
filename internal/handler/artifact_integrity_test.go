// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestFinalPDFMatchesDigest(t *testing.T) {
	body := []byte("immutable final")
	sum := sha256.Sum256(body)
	if !finalPDFMatchesDigest(body, sum[:]) {
		t.Fatal("matching final PDF rejected")
	}
	if finalPDFMatchesDigest([]byte("tampered"), sum[:]) {
		t.Fatal("tampered final PDF accepted")
	}
	if finalPDFMatchesDigest(body, nil) {
		t.Fatal("missing committed digest accepted")
	}
}

func TestContentAddressedArtifactMatches(t *testing.T) {
	body := []byte("immutable certificate")
	sum := sha256.Sum256(body)
	key := "org/o/documents/d/audit-" + hex.EncodeToString(sum[:]) + ".pdf"
	if !contentAddressedArtifactMatches(body, key, "audit", ".pdf") {
		t.Fatal("matching content-addressed certificate rejected")
	}
	if contentAddressedArtifactMatches([]byte("tampered"), key, "audit", ".pdf") {
		t.Fatal("tampered content-addressed certificate accepted")
	}
	if !contentAddressedArtifactMatches(body, "org/o/documents/d/audit.pdf", "audit", ".pdf") {
		t.Fatal("historical audit key should remain readable")
	}
}
