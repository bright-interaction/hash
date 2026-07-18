// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package timeline

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"
)

func mkEntry(id, kind, actor string, t time.Time) Entry {
	return Entry{
		ID:          id,
		Kind:        kind,
		ActorUserID: actor,
		CreatedAt:   t.UTC().Format(time.RFC3339),
		Occurrences: 1,
	}
}

func TestGroup_CollapsesSameActorSameKindWithinWindow(t *testing.T) {
	base := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	// Newest-first: caller already DESC-sorted via the SQL ORDER BY.
	entries := []Entry{
		mkEntry("3", "document.viewed", "alice", base.Add(3*time.Minute)),
		mkEntry("2", "document.viewed", "alice", base.Add(2*time.Minute)),
		mkEntry("1", "document.viewed", "alice", base),
	}
	out := Group(entries)
	if len(out) != 1 {
		t.Fatalf("want 1 grouped entry, got %d: %+v", len(out), out)
	}
	if out[0].Occurrences != 3 {
		t.Errorf("want occurrences=3, got %d", out[0].Occurrences)
	}
	if out[0].ID != "3" {
		t.Errorf("group head should be the newest event id, got %q", out[0].ID)
	}
}

func TestGroup_SplitsOnDifferentActor(t *testing.T) {
	base := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	entries := []Entry{
		mkEntry("2", "document.viewed", "alice", base.Add(1*time.Minute)),
		mkEntry("1", "document.viewed", "bob", base),
	}
	out := Group(entries)
	if len(out) != 2 {
		t.Fatalf("different actors should split: %+v", out)
	}
}

func TestGroup_SplitsOnDifferentKind(t *testing.T) {
	base := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	entries := []Entry{
		mkEntry("2", "document.sent", "alice", base.Add(1*time.Minute)),
		mkEntry("1", "document.viewed", "alice", base),
	}
	out := Group(entries)
	if len(out) != 2 {
		t.Fatalf("different kinds should split: %+v", out)
	}
}

func TestGroup_SplitsOnTimeWindowExceeded(t *testing.T) {
	base := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	entries := []Entry{
		mkEntry("2", "document.viewed", "alice", base.Add(6*time.Minute)),
		mkEntry("1", "document.viewed", "alice", base),
	}
	out := Group(entries)
	if len(out) != 2 {
		t.Fatalf("6-minute gap should split (window is 5 min): %+v", out)
	}
}

func TestGroup_Empty(t *testing.T) {
	out := Group(nil)
	if len(out) != 0 {
		t.Fatalf("empty in, empty out")
	}
}

func TestAttachDiffs_OnlyForUpdatedKind(t *testing.T) {
	base := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	entries := []Entry{
		mkEntry("a", "document.updated", "alice", base.Add(2*time.Minute)),
		mkEntry("b", "document.sent", "alice", base.Add(1*time.Minute)),
	}
	entries[0].DocumentID = "11111111-1111-1111-1111-111111111111"
	calls := 0
	lookup := func(docID string, et time.Time) (any, bool, error) {
		calls++
		if docID != "11111111-1111-1111-1111-111111111111" {
			t.Errorf("unexpected docID %q", docID)
		}
		return []string{"added:p", "modified:h"}, true, nil
	}
	out, err := AttachDiffs(entries, lookup)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if calls != 1 {
		t.Errorf("lookup should only fire for document.updated, got %d calls", calls)
	}
	if out[0].DiffChanges == nil {
		t.Errorf("expected DiffChanges on updated entry, got nil")
	}
	if out[1].DiffChanges != nil {
		t.Errorf("non-updated entry should not get DiffChanges, got %+v", out[1].DiffChanges)
	}
}

func TestAttachDiffs_NilLookupNoop(t *testing.T) {
	in := []Entry{mkEntry("a", "document.updated", "alice", time.Now())}
	out, err := AttachDiffs(in, nil)
	if err != nil {
		t.Fatalf("attach with nil lookup: %v", err)
	}
	if len(out) != 1 || out[0].DiffChanges != nil {
		t.Errorf("nil lookup must be a no-op, got %+v", out)
	}
}

func TestAttachActorEmails_PopulatesEmailsAcrossEntries(t *testing.T) {
	base := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	entries := []Entry{
		mkEntry("1", "document.sent", "alice", base),
		mkEntry("2", "document.viewed", "alice", base),
		mkEntry("3", "document.signed", "bob", base),
	}
	lookup := func(ids []string) (map[string]string, error) {
		out := map[string]string{}
		for _, id := range ids {
			out[id] = id + "@example.com"
		}
		return out, nil
	}
	out, err := AttachActorEmails(entries, lookup)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	for _, e := range out {
		want := e.ActorUserID + "@example.com"
		if e.ActorEmail != want {
			t.Errorf("entry %s: want email %q, got %q", e.ID, want, e.ActorEmail)
		}
	}
}

func TestExportCSV_StableColumnLayout(t *testing.T) {
	base := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	entries := []Entry{
		mkEntry("1", "document.sent", "alice", base),
	}
	entries[0].ActorEmail = "alice@example.com"
	entries[0].DocumentID = "doc-1"
	entries[0].Payload = []byte(`{"reason":"manual"}`)
	var buf bytes.Buffer
	if err := ExportCSV(&buf, entries); err != nil {
		t.Fatalf("export: %v", err)
	}
	r := csv.NewReader(&buf)
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want header + 1 row, got %d", len(rows))
	}
	header := strings.Join(rows[0], ",")
	for _, want := range []string{"timestamp", "kind", "actor_email", "document_id", "occurrences", "payload_json"} {
		if !strings.Contains(header, want) {
			t.Errorf("header missing column %q: %s", want, header)
		}
	}
	if rows[1][1] != "document.sent" {
		t.Errorf("kind column off: %v", rows[1])
	}
	if rows[1][2] != "alice@example.com" {
		t.Errorf("actor_email column off: %v", rows[1])
	}
}

func TestExportCSV_NilWriterErrors(t *testing.T) {
	if err := ExportCSV(nil, nil); err == nil {
		t.Fatal("expected error for nil writer")
	}
}
