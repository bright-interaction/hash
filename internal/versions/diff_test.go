// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package versions

import (
	"encoding/json"
	"testing"
)

// helper: build a minimal block tree JSON with stable IDs so the diff engine's
// id-matching path is exercised.
func tree(blocks ...map[string]any) []byte {
	t := map[string]any{
		"version": 1,
		"blocks":  blocks,
	}
	out, err := json.Marshal(t)
	if err != nil {
		panic(err)
	}
	return out
}

func block(id, kind, text string, attrs map[string]any) map[string]any {
	out := map[string]any{
		"id":   id,
		"type": kind,
		"text": text,
	}
	if attrs != nil {
		out["attrs"] = attrs
	}
	return out
}

func TestDiff_Empty(t *testing.T) {
	changes, err := Diff(nil, nil)
	if err != nil {
		t.Fatalf("diff empty: %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("expected 0 changes, got %d", len(changes))
	}
}

func TestDiff_Added(t *testing.T) {
	from := tree(block("a", "paragraph", "first", nil))
	to := tree(
		block("a", "paragraph", "first", nil),
		block("b", "paragraph", "second", nil),
	)
	changes, err := Diff(from, to)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("want 1 change, got %d: %+v", len(changes), changes)
	}
	if changes[0].Kind != ChangeAdded || changes[0].BlockID != "b" {
		t.Fatalf("unexpected change: %+v", changes[0])
	}
	if changes[0].ToText != "second" {
		t.Fatalf("missing to_text: %+v", changes[0])
	}
}

func TestDiff_Removed(t *testing.T) {
	from := tree(
		block("a", "paragraph", "first", nil),
		block("b", "paragraph", "second", nil),
	)
	to := tree(block("a", "paragraph", "first", nil))
	changes, err := Diff(from, to)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("want 1 change, got %d: %+v", len(changes), changes)
	}
	if changes[0].Kind != ChangeRemoved || changes[0].BlockID != "b" {
		t.Fatalf("unexpected change: %+v", changes[0])
	}
}

func TestDiff_Modified(t *testing.T) {
	from := tree(block("a", "paragraph", "first", nil))
	to := tree(block("a", "paragraph", "first edited", nil))
	changes, err := Diff(from, to)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if len(changes) != 1 || changes[0].Kind != ChangeModified {
		t.Fatalf("expected one Modified change, got %+v", changes)
	}
	if changes[0].FromText != "first" || changes[0].ToText != "first edited" {
		t.Fatalf("wrong from/to: %+v", changes[0])
	}
}

func TestDiff_Moved(t *testing.T) {
	from := tree(
		block("a", "paragraph", "first", nil),
		block("b", "paragraph", "second", nil),
	)
	to := tree(
		block("b", "paragraph", "second", nil),
		block("a", "paragraph", "first", nil),
	)
	changes, err := Diff(from, to)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if len(changes) != 2 {
		t.Fatalf("want 2 moves, got %d: %+v", len(changes), changes)
	}
	for _, ch := range changes {
		if ch.Kind != ChangeMoved {
			t.Fatalf("expected Moved, got %+v", ch)
		}
	}
}

func TestDiff_AttrChange(t *testing.T) {
	from := tree(block("h", "heading", "Title", map[string]any{"level": 1}))
	to := tree(block("h", "heading", "Title", map[string]any{"level": 2}))
	changes, err := Diff(from, to)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if len(changes) != 1 || changes[0].Kind != ChangeModified {
		t.Fatalf("expected Modified for attr change, got %+v", changes)
	}
	if changes[0].FromAttr == changes[0].ToAttr {
		t.Fatalf("attr summaries should differ: from=%q to=%q",
			changes[0].FromAttr, changes[0].ToAttr)
	}
}

func TestDiff_BlocksWithoutIDsGetParserAssignedIDs(t *testing.T) {
	// ParseTree assigns stable IDs to blocks missing them, so a fresh paragraph
	// and a different fresh paragraph hash to different IDs and look like one
	// remove + one add to the diff. This is correct behaviour: anonymous blocks
	// can't be matched across versions because there's nothing to match on.
	from := []byte(`{"version":1,"blocks":[{"type":"paragraph","text":"a"}]}`)
	to := []byte(`{"version":1,"blocks":[{"type":"paragraph","text":"b"}]}`)
	changes, err := Diff(from, to)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	// 1 added (in B) + 1 removed (in A); no matched modification
	if len(changes) != 2 {
		t.Fatalf("expected 2 unmatched changes for ID-less blocks, got %+v", changes)
	}
	kinds := map[ChangeKind]int{}
	for _, ch := range changes {
		kinds[ch.Kind]++
	}
	if kinds[ChangeAdded] != 1 || kinds[ChangeRemoved] != 1 {
		t.Fatalf("expected 1 added + 1 removed, got %v", kinds)
	}
}

func TestDiff_NestedBlocksFlattenedWithStablePositions(t *testing.T) {
	// bullet_list block with two nested items; modify one nested item
	from := tree(map[string]any{
		"id":   "list",
		"type": "bullet_list",
		"content": []map[string]any{
			block("li1", "list_item", "first", nil),
			block("li2", "list_item", "second", nil),
		},
	})
	to := tree(map[string]any{
		"id":   "list",
		"type": "bullet_list",
		"content": []map[string]any{
			block("li1", "list_item", "first", nil),
			block("li2", "list_item", "second edited", nil),
		},
	})
	changes, err := Diff(from, to)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("want 1 change in nested list, got %d: %+v", len(changes), changes)
	}
	if changes[0].BlockID != "li2" || changes[0].Kind != ChangeModified {
		t.Fatalf("unexpected change: %+v", changes[0])
	}
}

func TestSummarizeCounts(t *testing.T) {
	changes := []BlockChange{
		{Kind: ChangeAdded, BlockID: "a"},
		{Kind: ChangeAdded, BlockID: "b"},
		{Kind: ChangeRemoved, BlockID: "c"},
		{Kind: ChangeModified, BlockID: "d"},
		{Kind: ChangeMoved, BlockID: "e"},
	}
	c := SummarizeCounts(changes)
	if c.Added != 2 || c.Removed != 1 || c.Modified != 1 || c.Moved != 1 {
		t.Fatalf("counts off: %+v", c)
	}
}
