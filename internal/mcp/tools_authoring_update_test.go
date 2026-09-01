// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/recipients"
)

func TestUpdateBlockToolRegistered(t *testing.T) {
	s := New(Deps{})
	tool, ok := s.tools["update_block"]
	if !ok {
		t.Fatal("update_block must be present in the MCP catalogue")
	}
	if !tool.Write {
		t.Fatal("update_block must require write scope")
	}
	required, _ := tool.InputSchema["required"].([]string)
	for _, want := range []string{"document_id", "block_id", "block"} {
		found := false
		for _, got := range required {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("update_block schema missing required field %q: %v", want, required)
		}
	}
}

func TestNormalizeMCPRecipientUpdateRejectsExplicitEmpty(t *testing.T) {
	existing := &generated.Recipient{
		Email: "signer@example.test", Name: "Signer", Role: "signer", Locale: "en",
	}
	empty := ""
	_, err := normalizeMCPRecipientUpdate(existing, nil, &empty, nil, nil, nil)
	var validationErr *recipients.ValidationError
	if !errors.As(err, &validationErr) || validationErr.Field != "name" {
		t.Fatalf("explicit empty name error = %v, want name ValidationError", err)
	}
}

func TestNormalizeMCPRecipientUpdateRejectsUnsupportedInformationalRole(t *testing.T) {
	existing := &generated.Recipient{
		Email: "signer@example.test", Name: "Signer", Role: "signer", Locale: "en",
	}
	for _, role := range []string{"cc", "viewer"} {
		role := role
		_, err := normalizeMCPRecipientUpdate(existing, nil, nil, &role, nil, nil)
		var validationErr *recipients.ValidationError
		if !errors.As(err, &validationErr) || validationErr.Field != "role" {
			t.Fatalf("role %q error = %v, want role ValidationError", role, err)
		}
	}
}

func TestRecipientMutationToolsUseBoundedCustomRoleSchema(t *testing.T) {
	s := New(Deps{})
	for _, toolName := range []string{"add_recipient", "update_recipient"} {
		tool := s.tools[toolName]
		properties, _ := tool.InputSchema["properties"].(map[string]any)
		role, _ := properties["role"].(map[string]any)
		if pattern, _ := role["pattern"].(string); pattern != "^[a-z][a-z0-9_-]{0,63}$" {
			t.Fatalf("%s role pattern = %q, want bounded canonical custom roles", toolName, pattern)
		}
		description, _ := role["description"].(string)
		if !strings.Contains(description, "cc/viewer are unavailable") {
			t.Fatalf("%s role description still advertises unsupported informational delivery: %q", toolName, description)
		}
	}
}

func TestUpdateTopLevelBlock(t *testing.T) {
	tree := &blocks.Tree{Version: blocks.SchemaVersion, Blocks: []blocks.Block{
		{ID: "first", Type: blocks.TypeParagraph, Text: "before"},
		{ID: "second", Type: blocks.TypeParagraph, Text: "untouched"},
	}}
	replacement := blocks.Block{ID: "attempted-rename", Type: blocks.TypeParagraph, Text: "after"}
	if err := updateTopLevelBlock(tree, "first", replacement); err != nil {
		t.Fatalf("updateTopLevelBlock: %v", err)
	}
	if got := tree.Blocks[0]; got.ID != "first" || got.Text != "after" {
		t.Fatalf("replacement = %+v, want preserved id + new content", got)
	}
	if got := tree.Blocks[1].Text; got != "untouched" {
		t.Fatalf("sibling changed: %q", got)
	}
}

func TestUpdateTopLevelBlockRejectsUnknownID(t *testing.T) {
	tree := &blocks.Tree{Version: blocks.SchemaVersion, Blocks: []blocks.Block{
		{ID: "known", Type: blocks.TypeParagraph, Text: "original"},
	}}
	if err := updateTopLevelBlock(tree, "missing", blocks.Block{Type: blocks.TypeParagraph}); err == nil {
		t.Fatal("unknown block id should fail")
	}
	if got := tree.Blocks[0].Text; got != "original" {
		t.Fatalf("failed update mutated tree: %q", got)
	}
}
