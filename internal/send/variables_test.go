// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestValidateResolvedBlockVariables(t *testing.T) {
	tree := blocks.Tree{Version: 1, Blocks: []blocks.Block{
		{ID: "terms", Type: blocks.TypeParagraph, Text: "Agreement between {{provider}} and {{client}}"},
	}}
	blocksJSON, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		variables string
		wantErr   bool
		wantNames []string
	}{
		{name: "all resolved", variables: `{"provider":"Bright Interaction AB","client":"Example AB"}`},
		{name: "missing", variables: `{"provider":"Bright Interaction AB"}`, wantErr: true, wantNames: []string{"client"}},
		{name: "blank", variables: `{"provider":"Bright Interaction AB","client":"  "}`, wantErr: true, wantNames: []string{"client"}},
		{name: "nested token", variables: `{"provider":"Bright Interaction AB","client":"{{customer}}"}`, wantErr: true, wantNames: []string{"client"}},
		{name: "invalid shape", variables: `[]`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := &generated.Document{SourceKind: "blocks", BlocksJson: blocksJSON, VariablesJson: []byte(tt.variables)}
			err := validateResolvedBlockVariables(doc)
			if tt.wantErr != errors.Is(err, ErrUnresolvedVariables) {
				t.Fatalf("error = %v, want ErrUnresolvedVariables=%v", err, tt.wantErr)
			}
			for _, name := range tt.wantNames {
				if !strings.Contains(err.Error(), name) {
					t.Fatalf("error %q does not identify %q", err, name)
				}
			}
		})
	}
}

func TestValidateResolvedBlockVariablesSkipsPDF(t *testing.T) {
	doc := &generated.Document{SourceKind: "pdf", VariablesJson: []byte(`not-json`)}
	if err := validateResolvedBlockVariables(doc); err != nil {
		t.Fatalf("PDF validation = %v, want nil", err)
	}
}

func TestValidateResolvedBlockVariablesRejectsUnsupportedOrMalformedPlaceholders(t *testing.T) {
	tests := []struct {
		name  string
		block blocks.Block
	}{
		{
			name:  "malformed name",
			block: blocks.Block{ID: "bad-name", Type: blocks.TypeParagraph, Text: "Customer: {{client-name}}"},
		},
		{
			name:  "unclosed token",
			block: blocks.Block{ID: "unclosed", Type: blocks.TypeParagraph, Text: "Customer: {{client"},
		},
		{
			name:  "orphan close",
			block: blocks.Block{ID: "close", Type: blocks.TypeParagraph, Text: "Customer: client}}"},
		},
		{
			name:  "triple braces",
			block: blocks.Block{ID: "triple", Type: blocks.TypeParagraph, Text: "Customer: {{{client}}}"},
		},
		{
			name:  "code is literal",
			block: blocks.Block{ID: "code", Type: blocks.TypeCode, Text: "{{client}}"},
		},
		{
			name:  "raw html is literal",
			block: blocks.Block{ID: "raw", Type: blocks.TypeRawHTML, Text: "<p>{{client}}</p>"},
		},
		{
			name: "table header is literal",
			block: blocks.Block{
				ID: "table", Type: blocks.TypeTable,
				Attrs: map[string]any{"columns": []any{"{{client}}"}},
				Rows:  [][]string{{"Example AB"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := blocks.Tree{Version: 1, Blocks: []blocks.Block{tt.block}}
			blocksJSON, err := json.Marshal(tree)
			if err != nil {
				t.Fatal(err)
			}
			doc := &generated.Document{
				SourceKind:    "blocks",
				BlocksJson:    blocksJSON,
				VariablesJson: []byte(`{"client":"Example AB"}`),
			}
			if err := validateResolvedBlockVariables(doc); !errors.Is(err, ErrUnresolvedVariables) {
				t.Fatalf("validation error = %v, want ErrUnresolvedVariables", err)
			}
		})
	}
}

func TestValidateResolvedBlockVariablesAllowsSubstitutedTableCells(t *testing.T) {
	tree := blocks.Tree{Version: 1, Blocks: []blocks.Block{{
		ID: "table", Type: blocks.TypeTable,
		Attrs: map[string]any{"columns": []any{"Customer"}},
		Rows:  [][]string{{"{{client}}"}},
	}}}
	blocksJSON, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	doc := &generated.Document{
		SourceKind:    "blocks",
		BlocksJson:    blocksJSON,
		VariablesJson: []byte(`{"client":"Example AB"}`),
	}
	if err := validateResolvedBlockVariables(doc); err != nil {
		t.Fatalf("substituted table cell rejected: %v", err)
	}
}

func TestValidateResolvedBlockVariablesRequiresConditionalInputs(t *testing.T) {
	tree := blocks.Tree{Version: 1, Blocks: []blocks.Block{{
		ID:    "conditional-price",
		Type:  blocks.TypeConditional,
		Attrs: map[string]any{"expression": `var(include_price) == "yes"`},
		Content: []blocks.Block{{
			ID: "price", Type: blocks.TypeParagraph, Text: "Price: {{amount}}",
		}},
	}}}
	blocksJSON, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	doc := func(variables string) *generated.Document {
		return &generated.Document{SourceKind: "blocks", BlocksJson: blocksJSON, VariablesJson: []byte(variables)}
	}

	for _, variables := range []string{
		`{"amount":"1000"}`,
		`{"include_price":" ","amount":"1000"}`,
	} {
		if err := validateResolvedBlockVariables(doc(variables)); !errors.Is(err, ErrUnresolvedVariables) {
			t.Fatalf("variables %s error = %v, want ErrUnresolvedVariables", variables, err)
		}
		if err := validateResolvedSealedSnapshot(doc(variables), nil); !errors.Is(err, ErrUnresolvedVariables) {
			t.Fatalf("recovery variables %s error = %v, want ErrUnresolvedVariables", variables, err)
		}
	}
	if err := validateResolvedBlockVariables(doc(`{"include_price":"yes","amount":"1000"}`)); err != nil {
		t.Fatalf("resolved conditional rejected: %v", err)
	}
}

func TestValidateResolvedBlockVariablesRejectsMalformedConditionalDuringRecovery(t *testing.T) {
	// ParseTree performs the same strict expression validation for legacy rows
	// as it does for newly authored trees, so recovery cannot silently evaluate
	// a trailing or partial expression as false.
	tree := blocks.Tree{Version: 1, Blocks: []blocks.Block{{
		ID:    "conditional",
		Type:  blocks.TypeConditional,
		Attrs: map[string]any{"expression": `var(include_clause) == "yes" trailing`},
		Content: []blocks.Block{{
			ID: "clause", Type: blocks.TypeParagraph, Text: "Important clause",
		}},
	}}}
	blocksJSON, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	doc := &generated.Document{
		SourceKind:    "blocks",
		BlocksJson:    blocksJSON,
		VariablesJson: []byte(`{"include_clause":"yes"}`),
	}
	if err := validateResolvedSealedSnapshot(doc, nil); !errors.Is(err, ErrUnresolvedVariables) {
		t.Fatalf("malformed recovery condition error = %v, want ErrUnresolvedVariables", err)
	}
}

func TestValidateResolvedSealedSnapshotRechecksDurableDocuments(t *testing.T) {
	tree := blocks.Tree{Version: 1, Blocks: []blocks.Block{
		{ID: "party", Type: blocks.TypeParagraph, Text: "Customer: {{client}}"},
	}}
	blocksJSON, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	resolved := &generated.Document{
		SourceKind:    "blocks",
		BlocksJson:    blocksJSON,
		VariablesJson: []byte(`{"client":"Example AB"}`),
	}
	unresolved := &generated.Document{
		SourceKind:    "blocks",
		BlocksJson:    blocksJSON,
		VariablesJson: []byte(`{}`),
	}

	if err := validateResolvedSealedSnapshot(resolved, []*generated.Document{resolved}); err != nil {
		t.Fatalf("resolved sealing snapshot rejected: %v", err)
	}
	if err := validateResolvedSealedSnapshot(unresolved, nil); !errors.Is(err, ErrUnresolvedVariables) {
		t.Fatalf("unresolved root error = %v, want ErrUnresolvedVariables", err)
	}
	if err := validateResolvedSealedSnapshot(
		&generated.Document{SourceKind: "pdf"},
		[]*generated.Document{unresolved},
	); !errors.Is(err, ErrUnresolvedVariables) {
		t.Fatalf("unresolved envelope child error = %v, want ErrUnresolvedVariables", err)
	}
}

func TestValidateResolvedBlockVariablesRejectsWithdrawnLegalStarterCopies(t *testing.T) {
	for _, claim := range []string{
		"Atomicsite-binären levereras under sin öppna licens Apache 2.0, vilket redan i sig ger kunden rättigheter.",
		"Ett personuppgiftsbiträdesavtal (Bilaga A) gäller från driftstart och har företräde.",
		"DRAFT KIT v1 (auto-seeded by Hash for jurisdiction=SE). Review with counsel before use.",
	} {
		tree := blocks.Tree{Version: 1, Blocks: []blocks.Block{
			{ID: "withdrawn-claim", Type: blocks.TypeParagraph, Text: claim},
		}}
		blocksJSON, err := json.Marshal(tree)
		if err != nil {
			t.Fatal(err)
		}
		doc := &generated.Document{SourceKind: "blocks", BlocksJson: blocksJSON, VariablesJson: []byte(`{}`)}
		if err := validateResolvedBlockVariables(doc); !errors.Is(err, ErrUnsafeBuiltInLegalDraft) {
			t.Fatalf("withdrawn claim error = %v, want ErrUnsafeBuiltInLegalDraft", err)
		}
	}
}
