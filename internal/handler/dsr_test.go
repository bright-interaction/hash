// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestIsValidDSRKind(t *testing.T) {
	for _, k := range []string{"access", "rectification", "erasure", "restriction", "portability", "objection"} {
		if !isValidDSRKind(k) {
			t.Errorf("valid kind %q rejected", k)
		}
	}
	for _, k := range []string{"", "DELETE", "all", "delete", "ACCESS", "Access"} {
		if isValidDSRKind(k) {
			t.Errorf("invalid kind %q accepted", k)
		}
	}
}

func TestOnlyErasureHasAutomatedDSRFulfillment(t *testing.T) {
	for _, kind := range []string{"access", "rectification", "restriction", "portability", "objection", ""} {
		if supportsAutomatedDSRFulfillment(kind) {
			t.Errorf("unsupported request kind %q can be marked fulfilled", kind)
		}
	}
	if !supportsAutomatedDSRFulfillment("erasure") {
		t.Fatal("erasure automation unexpectedly disabled")
	}
}

func TestSignerPrivacyRequestRemainsAvailableInEveryNoticeState(t *testing.T) {
	for _, status := range []string{"sent", "in_progress", "changes_requested"} {
		if !documentAcceptsSignerPrivacyRequest(status) {
			t.Errorf("notice-visible status %q rejected a signer privacy request", status)
		}
	}
	for _, status := range []string{"", "draft", "sealing", "finalizing", "completed", "declined", "voided", "expired"} {
		if documentAcceptsSignerPrivacyRequest(status) {
			t.Errorf("inactive or unavailable status %q accepted a signer privacy request", status)
		}
	}
}

func TestIsValidDSRStatusTransition(t *testing.T) {
	allow := []struct{ from, to string }{
		{"open", "in_progress"},
		{"open", "fulfilled"},
		{"open", "denied"},
		{"open", "withdrawn"},
		{"in_progress", "fulfilled"},
		{"in_progress", "denied"},
		{"in_progress", "withdrawn"},
		{"denied", "in_progress"},
		{"withdrawn", "in_progress"},
	}
	for _, c := range allow {
		if !IsValidDSRStatusTransition(c.from, c.to) {
			t.Errorf("expected %s -> %s allowed", c.from, c.to)
		}
	}
	deny := []struct{ from, to string }{
		{"fulfilled", "open"},        // terminal
		{"fulfilled", "in_progress"}, // terminal
		{"open", "open"},             // no self
		{"open", "garbage"},          // unknown
		{"", "open"},                 // unknown source
	}
	for _, c := range deny {
		if IsValidDSRStatusTransition(c.from, c.to) {
			t.Errorf("expected %s -> %s denied", c.from, c.to)
		}
	}
}

func TestAnonymizedEmail_IncludesRequestID(t *testing.T) {
	id := uuid.New()
	got := AnonymizedEmail(id)
	if !strings.Contains(got, id.String()) {
		t.Errorf("anonymized email should include request id; got %q", got)
	}
	if !strings.HasSuffix(got, "@dsr.invalid") {
		t.Errorf("anonymized email should use the @dsr.invalid reserved TLD; got %q", got)
	}
}

func TestAnonymizedEmail_RFCInvalidDomain(t *testing.T) {
	// RFC 6761 reserves .invalid for never-routed test domains; using
	// it here guarantees no real deliveries to anonymized rows.
	got := AnonymizedEmail(uuid.New())
	if !strings.HasSuffix(got, ".invalid") {
		t.Errorf("anonymized email must end with .invalid: %q", got)
	}
}

func TestAnonymizationMarker_HumanReadable(t *testing.T) {
	if !strings.Contains(AnonymizationMarker, "redacted") {
		t.Errorf("marker should be human-recognisable; got %q", AnonymizationMarker)
	}
}

func TestNonZero(t *testing.T) {
	if nonZero(uuid.Nil) != nil {
		t.Error("nil uuid should map to nil pointer")
	}
	u := uuid.New()
	got := nonZero(u)
	if got == nil || *got != u {
		t.Errorf("non-nil uuid lost in nonZero; got %v want %v", got, u)
	}
}

func TestDocumentAllowsDestructiveErasureFailsClosedDuringEvidenceCeremony(t *testing.T) {
	for _, status := range []string{"sealing", "sent", "in_progress", "changes_requested", "finalizing"} {
		doc := &generated.Document{Status: status}
		if documentAllowsDestructiveErasure(doc, false) {
			t.Errorf("active status %q allowed destructive erasure", status)
		}
	}
	for _, status := range []string{"draft", "declined", "voided", "expired"} {
		doc := &generated.Document{Status: status}
		if !documentAllowsDestructiveErasure(doc, false) {
			t.Errorf("inactive unsigned status %q rejected erasure", status)
		}
		if documentAllowsDestructiveErasure(doc, true) {
			t.Errorf("status %q with captured signatures allowed unsealed evidence erasure", status)
		}
	}
}

func TestDocumentAllowsDestructiveErasureRequiresCompletePublishedTuple(t *testing.T) {
	text := func(value string) pgtype.Text { return pgtype.Text{String: value, Valid: true} }
	doc := &generated.Document{
		Status: "completed", EvidenceVersionPinsRequired: true,
		FinalPdfKey: text("final.pdf"), FinalPdfSha: make([]byte, 32), FinalPdfVersionID: text("final-version-1"),
		AuditCertKey: text("cert.pdf"), AuditCertSha256: make([]byte, 32), AuditCertVersionID: text("cert-version-1"),
		AuditPayloadKey: text("payload.txt"), AuditPayloadSha256: make([]byte, 32), AuditPayloadVersionID: text("payload-version-1"),
		AuditSignatureKey: text("signature.txt"), AuditSignatureSha256: make([]byte, 32), AuditSignatureVersionID: text("signature-version-1"),
	}
	if !documentAllowsDestructiveErasure(doc, true) {
		t.Fatal("completed document with a published evidence tuple rejected erasure")
	}
	doc.AuditSignatureSha256 = nil
	if documentAllowsDestructiveErasure(doc, true) {
		t.Fatal("completed document with an incomplete evidence tuple allowed erasure")
	}
	doc.AuditSignatureSha256 = make([]byte, 32)
	doc.EvidenceVersionPinsRequired = false
	if documentAllowsDestructiveErasure(doc, true) {
		t.Fatal("completed legacy document without exact VersionIds allowed erasure")
	}
	doc.EvidenceVersionPinsRequired = true
	doc.AuditSignatureVersionID = text(" hash:unversioned-development ")
	if documentAllowsDestructiveErasure(doc, true) {
		t.Fatal("completed document with a development VersionId sentinel allowed erasure")
	}
}
