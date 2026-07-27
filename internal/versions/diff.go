// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package versions

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/bright-interaction/hash/internal/blocks"
)

// ChangeKind is one of added, removed, modified, moved. Block-level diff is
// what the negotiation copilot (#3), timeline UI (#8.8), and evidence export
// (#10) all consume; finer-grained text diff is left to the frontend.
type ChangeKind string

const (
	ChangeAdded    ChangeKind = "added"
	ChangeRemoved  ChangeKind = "removed"
	ChangeModified ChangeKind = "modified"
	ChangeMoved    ChangeKind = "moved"
)

// BlockChange describes one block-level change between two versions. Position
// is the 0-indexed slot in the AFTER tree (or BEFORE if Kind=ChangeRemoved).
// FromText/ToText carry the rendered text of the block for human display.
type BlockChange struct {
	Kind     ChangeKind `json:"kind"`
	BlockID  string     `json:"block_id"`
	Type     string     `json:"type,omitempty"`
	Position int        `json:"position"`
	FromText string     `json:"from_text,omitempty"`
	ToText   string     `json:"to_text,omitempty"`
	FromAttr string     `json:"from_attr,omitempty"`
	ToAttr   string     `json:"to_attr,omitempty"`
}

// DiffResult bundles the change list with high-level counts so callers can
// render a "5 added, 2 removed, 1 modified" summary without iterating.
type DiffResult struct {
	From    DiffSide      `json:"from"`
	To      DiffSide      `json:"to"`
	Changes []BlockChange `json:"changes"`
	Counts  DiffCounts    `json:"counts"`
}

// DiffSide is the version pointer for either side of a diff.
type DiffSide struct {
	VersionID  string `json:"version_id"`
	VersionNo  int32  `json:"version_no"`
	DocumentID string `json:"document_id"`
	BlockCount int    `json:"block_count"`
	NameAtRev  string `json:"name_at_rev"`
	HumanLabel string `json:"human_label,omitempty"`
}

// DiffCounts are the per-kind tallies. Callers use them for compact summaries.
type DiffCounts struct {
	Added    int `json:"added"`
	Removed  int `json:"removed"`
	Modified int `json:"modified"`
	Moved    int `json:"moved"`
}

// Diff compares two block trees and returns block-level changes keyed by
// block ID. Stable IDs are guaranteed by the editor (BlockIDExtension in
// frontend/src/lib/components/BlockEditor/nodes.ts), so we can match blocks
// across versions even when their position changes. Without stable IDs the
// diff degrades to a positional compare; we annotate added/removed but cannot
// detect moves.
func Diff(from, to []byte) ([]BlockChange, error) {
	a, err := parseTreeOrEmpty(from)
	if err != nil {
		return nil, fmt.Errorf("diff: parse from: %w", err)
	}
	b, err := parseTreeOrEmpty(to)
	if err != nil {
		return nil, fmt.Errorf("diff: parse to: %w", err)
	}

	// flatten both trees so nested content blocks (lists, tables) compare too
	flatA := flattenWithPosition(a.Blocks, 0)
	flatB := flattenWithPosition(b.Blocks, 0)

	idxA := indexByID(flatA)
	idxB := indexByID(flatB)

	changes := make([]BlockChange, 0)

	// pass 1: removed (in A but not B) and modified/moved (in both)
	idsA := sortedIDs(idxA)
	for _, id := range idsA {
		entryA := idxA[id]
		entryB, ok := idxB[id]
		if !ok {
			changes = append(changes, BlockChange{
				Kind:     ChangeRemoved,
				BlockID:  id,
				Type:     string(entryA.Block.Type),
				Position: entryA.Position,
				FromText: entryA.Block.Text,
			})
			continue
		}
		if !blockEquivalent(entryA.Block, entryB.Block) {
			changes = append(changes, BlockChange{
				Kind:     ChangeModified,
				BlockID:  id,
				Type:     string(entryB.Block.Type),
				Position: entryB.Position,
				FromText: entryA.Block.Text,
				ToText:   entryB.Block.Text,
				FromAttr: attrSummary(entryA.Block),
				ToAttr:   attrSummary(entryB.Block),
			})
		} else if entryA.Position != entryB.Position {
			changes = append(changes, BlockChange{
				Kind:     ChangeMoved,
				BlockID:  id,
				Type:     string(entryB.Block.Type),
				Position: entryB.Position,
			})
		}
	}

	// pass 2: added (in B but not A)
	idsB := sortedIDs(idxB)
	for _, id := range idsB {
		if _, exists := idxA[id]; exists {
			continue
		}
		entryB := idxB[id]
		changes = append(changes, BlockChange{
			Kind:     ChangeAdded,
			BlockID:  id,
			Type:     string(entryB.Block.Type),
			Position: entryB.Position,
			ToText:   entryB.Block.Text,
		})
	}

	// stable ordering: by position, then by id
	sort.SliceStable(changes, func(i, j int) bool {
		if changes[i].Position != changes[j].Position {
			return changes[i].Position < changes[j].Position
		}
		return changes[i].BlockID < changes[j].BlockID
	})

	return changes, nil
}

// SummarizeCounts walks the change list and returns aggregate counts.
func SummarizeCounts(changes []BlockChange) DiffCounts {
	var c DiffCounts
	for _, ch := range changes {
		switch ch.Kind {
		case ChangeAdded:
			c.Added++
		case ChangeRemoved:
			c.Removed++
		case ChangeModified:
			c.Modified++
		case ChangeMoved:
			c.Moved++
		}
	}
	return c
}

// flatEntry is an internal flattening helper. Position is a stable depth-first
// counter so moves across nesting are detected the same way as moves within
// the top-level list.
type flatEntry struct {
	Block    blocks.Block
	Position int
}

func flattenWithPosition(in []blocks.Block, startPos int) []flatEntry {
	out := make([]flatEntry, 0, len(in))
	pos := startPos
	for _, b := range in {
		out = append(out, flatEntry{Block: b, Position: pos})
		pos++
		if len(b.Content) > 0 {
			nested := flattenWithPosition(b.Content, pos)
			out = append(out, nested...)
			pos += len(nested)
		}
	}
	return out
}

func indexByID(entries []flatEntry) map[string]flatEntry {
	out := make(map[string]flatEntry, len(entries))
	for _, e := range entries {
		if e.Block.ID == "" {
			// Skip entries without stable IDs; they can't be matched across
			// versions. The editor guarantees IDs for normal blocks, but
			// migrations or bad imports may have produced ID-less blocks.
			continue
		}
		out[e.Block.ID] = e
	}
	return out
}

func sortedIDs(m map[string]flatEntry) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func blockEquivalent(a, b blocks.Block) bool {
	if a.Type != b.Type {
		return false
	}
	if a.Text != b.Text {
		return false
	}
	if !attrsEqual(a.Attrs, b.Attrs) {
		return false
	}
	if !rowsEqual(a.Rows, b.Rows) {
		return false
	}
	// children compared structurally via flatten+id pass; this guard only
	// answers "are A and B themselves equivalent ignoring children", which is
	// what the caller wants when classifying modified vs moved.
	return true
}

func attrsEqual(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok {
			return false
		}
		// Compare via JSON to dodge float/int cross-type pitfalls cheaply.
		ja, _ := json.Marshal(va)
		jb, _ := json.Marshal(vb)
		if string(ja) != string(jb) {
			return false
		}
	}
	return true
}

func rowsEqual(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}

func attrSummary(b blocks.Block) string {
	if len(b.Attrs) == 0 {
		return ""
	}
	out, err := json.Marshal(b.Attrs)
	if err != nil {
		return ""
	}
	return string(out)
}

func parseTreeOrEmpty(raw []byte) (*blocks.Tree, error) {
	if len(raw) == 0 {
		return &blocks.Tree{}, nil
	}
	return blocks.ParseTree(raw)
}
