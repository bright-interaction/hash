// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package envelopes

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestManifestCanonicalSHAStable(t *testing.T) {
	m := Manifest{
		SchemaVersion: 1,
		EnvelopeID:    "11111111-1111-1111-1111-111111111111",
		EnvelopeTitle: "Acme Acquisition Package",
		Entries: []ManifestEntry{
			{ChildID: "aaa", Title: "Master Agreement", Position: 1, Status: "completed", ContentSnapshotSHA256: "deadbeef"},
			{ChildID: "bbb", Title: "DPA", Position: 2, Status: "completed", ContentSnapshotSHA256: "cafebabe"},
		},
	}
	m1 := m
	m2 := m
	m1.ManifestSHA = canonicalSHA(m1.canonicalBytes())
	m2.ManifestSHA = canonicalSHA(m2.canonicalBytes())
	if m1.ManifestSHA != m2.ManifestSHA {
		t.Fatalf("identical inputs produced different hashes: %s vs %s", m1.ManifestSHA, m2.ManifestSHA)
	}
	if _, err := hex.DecodeString(m1.ManifestSHA); err != nil {
		t.Fatalf("manifest hash should be hex: %v", err)
	}
}

func TestManifestCanonicalSHAChangesOnEdit(t *testing.T) {
	base := Manifest{
		EnvelopeID:    "11111111-1111-1111-1111-111111111111",
		EnvelopeTitle: "X",
		Entries: []ManifestEntry{
			{ChildID: "aaa", Title: "Master", Position: 1, ContentSnapshotSHA256: "deadbeef"},
		},
	}
	tampered := base
	tampered.Entries = append([]ManifestEntry{}, base.Entries...)
	tampered.Entries[0].ContentSnapshotSHA256 = "tampered"

	if canonicalSHA(base.canonicalBytes()) == canonicalSHA(tampered.canonicalBytes()) {
		t.Fatal("tampering with a child hash should change the manifest hash")
	}
}

func TestHTMLSectionEmpty(t *testing.T) {
	m := Manifest{}
	if got := m.HTMLSection(); got != "" {
		t.Fatalf("empty manifest should emit empty section, got %q", got)
	}
}

func TestHTMLSectionEmitsTableAndManifestHash(t *testing.T) {
	m := Manifest{
		EnvelopeID:    "abc",
		EnvelopeTitle: "Acme",
		Entries: []ManifestEntry{
			{ChildID: "c1", Title: "Master Agreement", Position: 1, Status: "completed", ContentSnapshotSHA256: "deadbeef"},
			{ChildID: "c2", Title: "DPA", Position: 2, Status: "in_progress", ContentSnapshotSHA256: "cafebabe"},
		},
	}
	m.ManifestSHA = canonicalSHA(m.canonicalBytes())
	html := m.HTMLSection()
	for _, want := range []string{
		"Envelope manifest",
		"Master Agreement",
		"DPA",
		"deadbeef",
		"cafebabe",
		"content-snapshot hash",
		m.ManifestSHA,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTMLSection missing %q in:\n%s", want, html)
		}
	}
}

func TestHTMLSectionEscapesUntrustedTitle(t *testing.T) {
	m := Manifest{
		EnvelopeID:    "abc",
		EnvelopeTitle: "Acme",
		Entries: []ManifestEntry{
			{ChildID: "c1", Title: "<script>alert(1)</script>", Position: 1, Status: "completed", ContentSnapshotSHA256: "deadbeef"},
		},
	}
	html := m.HTMLSection()
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatalf("HTMLSection must escape angle brackets in titles: %s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatalf("expected escaped script tag, got %s", html)
	}
}

func TestTerminalManifestMatchesPersistedCompletedChildren(t *testing.T) {
	envelope := &generated.Document{
		ID:         uuid.New(),
		Name:       "Acquisition package",
		IsEnvelope: true,
		Status:     "finalizing",
	}
	children := []*generated.Document{
		{
			ID: uuid.New(), Name: "MSA", SourceKind: "blocks", Status: "finalizing",
			BlocksJson:       []byte(`{"version":1,"blocks":[{"id":"a","type":"paragraph","text":"Frozen MSA"}]}`),
			VariablesJson:    []byte(`{"price":"100"}`),
			ParentEnvelopeID: pgtype.UUID{Bytes: envelope.ID, Valid: true},
			EnvelopePosition: pgtype.Int4{Int32: 1, Valid: true},
		},
		{
			ID: uuid.New(), Name: "DPA", SourceKind: "blocks", Status: "finalizing",
			BlocksJson:       []byte(`{"version":1,"blocks":[{"id":"b","type":"paragraph","text":"Frozen DPA"}]}`),
			VariablesJson:    []byte(`{}`),
			ParentEnvelopeID: pgtype.UUID{Bytes: envelope.ID, Valid: true},
			EnvelopePosition: pgtype.Int4{Int32: 2, Valid: true},
		},
	}

	terminal, err := BuildTerminalManifest(envelope, children)
	if err != nil {
		t.Fatalf("BuildTerminalManifest: %v", err)
	}
	if terminal.SchemaVersion != 2 {
		t.Fatalf("schema_version = %d, want 2", terminal.SchemaVersion)
	}
	for i, entry := range terminal.Entries {
		if entry.Status != "completed" {
			t.Errorf("entry %d status = %q, want completed", i, entry.Status)
		}
		if len(entry.ContentSnapshotSHA256) != 64 {
			t.Errorf("entry %d snapshot sha = %q, want 64 hex chars", i, entry.ContentSnapshotSHA256)
		}
		if _, err := hex.DecodeString(entry.ContentSnapshotSHA256); err != nil {
			t.Errorf("entry %d snapshot sha is not hex: %v", i, err)
		}
	}
	children[0].Status = "voided"
	if _, err := BuildTerminalManifest(envelope, children); err == nil {
		t.Fatal("terminal manifest must reject a child that left the active envelope lifecycle")
	}
	children[0].Status = "finalizing"

	// This is the persisted state written by CompleteEnvelopeChildren. The
	// combined final artifact metadata changes, but the recomputable legal
	// content commitment must remain byte-for-byte identical.
	envelope.Status = "completed"
	for _, child := range children {
		child.Status = "completed"
		child.FinalPdfKey = pgtype.Text{String: "org/x/documents/envelope/final.pdf", Valid: true}
		child.FinalPdfSha = []byte("aggregate-final-pdf-digest-value")
	}
	persisted, err := buildManifest(envelope, children, false)
	if err != nil {
		t.Fatalf("build persisted manifest: %v", err)
	}
	if terminal.ManifestSHA != persisted.ManifestSHA {
		t.Fatalf("signed terminal manifest %s != persisted manifest %s", terminal.ManifestSHA, persisted.ManifestSHA)
	}
}

func TestContentSnapshotDigestChangesWithFrozenVariables(t *testing.T) {
	child := &generated.Document{
		ID: uuid.New(), SourceKind: "blocks",
		BlocksJson:    []byte(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"Price {{price}}"}]}`),
		VariablesJson: []byte(`{"price":"100"}`),
	}
	before, err := contentSnapshotSHA(child)
	if err != nil {
		t.Fatal(err)
	}
	child.VariablesJson = []byte(`{"price":"200"}`)
	after, err := contentSnapshotSHA(child)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("changing frozen variables must change the child content commitment")
	}
}
