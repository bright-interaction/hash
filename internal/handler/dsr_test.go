package handler

import (
	"strings"
	"testing"

	"github.com/google/uuid"
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
