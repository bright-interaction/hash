// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// ── Schema + Validate ────────────────────────────────────────────────────

func TestParseTree_Empty(t *testing.T) {
	tree, err := ParseTree(nil)
	if err != nil {
		t.Fatalf("nil bytes: %v", err)
	}
	if tree.Version != SchemaVersion {
		t.Errorf("version = %d want %d", tree.Version, SchemaVersion)
	}
}

func TestParseTree_GeneratesIDs(t *testing.T) {
	raw := `{"version":1,"blocks":[{"type":"paragraph","text":"hello"}]}`
	tree, err := ParseTree([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tree.Blocks[0].ID == "" {
		t.Error("missing id was not generated")
	}
}

func TestValidate_DuplicateID(t *testing.T) {
	tree := &Tree{
		Version: 1,
		Blocks: []Block{
			{ID: "x", Type: TypeParagraph, Text: "a"},
			{ID: "x", Type: TypeParagraph, Text: "b"},
		},
	}
	err := Validate(tree)
	if !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("want ErrDuplicateID, got %v", err)
	}
}

func TestValidate_UnknownType(t *testing.T) {
	tree := &Tree{Version: 1, Blocks: []Block{{Type: "lol_no", Text: "x"}}}
	err := Validate(tree)
	if !errors.Is(err, ErrUnknownType) {
		t.Fatalf("want ErrUnknownType, got %v", err)
	}
}

func TestValidate_FutureVersionRejected(t *testing.T) {
	tree := &Tree{Version: 99}
	if err := Validate(tree); !errors.Is(err, ErrSchemaVersion) {
		t.Errorf("want ErrSchemaVersion, got %v", err)
	}
}

func TestValidate_ContentOnNonContainer(t *testing.T) {
	tree := &Tree{
		Version: 1,
		Blocks: []Block{
			{
				Type:    TypeParagraph,
				Content: []Block{{Type: TypeParagraph, Text: "nested"}},
			},
		},
	}
	if err := Validate(tree); !errors.Is(err, ErrInvalidBlock) {
		t.Errorf("want ErrInvalidBlock, got %v", err)
	}
}

func TestValidate_SignatureFieldNeedsRecipient(t *testing.T) {
	tree := &Tree{
		Version: 1,
		Blocks:  []Block{{Type: TypeSignatureField}},
	}
	if err := Validate(tree); !errors.Is(err, ErrInvalidBlock) {
		t.Errorf("want ErrInvalidBlock, got %v", err)
	}
}

func TestValidate_ImageNeedsStorageKey(t *testing.T) {
	tree := &Tree{Version: 1, Blocks: []Block{{Type: TypeImage}}}
	if err := Validate(tree); !errors.Is(err, ErrInvalidBlock) {
		t.Errorf("want ErrInvalidBlock, got %v", err)
	}
}

func TestSchemaJSON_AllTypesEnumerated(t *testing.T) {
	out := SchemaJSON()
	types, ok := out["types"].([]map[string]any)
	if !ok {
		t.Fatal("types missing or wrong shape")
	}
	if len(types) != len(AllTypes()) {
		t.Errorf("got %d type entries, want %d", len(types), len(AllTypes()))
	}
}

// ── Variable substitution ─────────────────────────────────────────────────

func TestSubstitute_BasicAndDotted(t *testing.T) {
	got := Substitute("hello {{name}}, signed on {{document.signed_date}}",
		map[string]string{"name": "Tom", "document.signed_date": "2026-05-09"})
	want := "hello Tom, signed on 2026-05-09"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSubstitute_UnknownLeavesToken(t *testing.T) {
	got := Substitute("hello {{missing}}", map[string]string{})
	if got != "hello {{missing}}" {
		t.Errorf("got %q, want token preserved", got)
	}
}

func TestSubstitute_NoTokens(t *testing.T) {
	if got := Substitute("plain", nil); got != "plain" {
		t.Errorf("got %q", got)
	}
}

func TestExtractVariableNames(t *testing.T) {
	tree := &Tree{
		Version: 1,
		Blocks: []Block{
			{Type: TypeParagraph, Text: "{{a}} {{b}}"},
			{Type: TypeDynamicVar, Attrs: map[string]any{"name": "c"}},
			{Type: TypeTable, Attrs: map[string]any{"columns": []any{"col"}},
				Rows: [][]string{{"{{d}}"}}},
		},
	}
	names := ExtractVariableNames(tree)
	got := map[string]bool{}
	for _, n := range names {
		got[n] = true
	}
	for _, want := range []string{"a", "b", "c", "d"} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, names)
		}
	}
}

// ── Conditionals ──────────────────────────────────────────────────────────

func TestEvalCondition_Comparisons(t *testing.T) {
	cases := []struct {
		expr string
		vars map[string]string
		want bool
	}{
		{`var(country) == "SE"`, map[string]string{"country": "SE"}, true},
		{`var(country) == "SE"`, map[string]string{"country": "US"}, false},
		{`var(country) != "US"`, map[string]string{"country": "SE"}, true},
		{`var(amount) > 10000`, map[string]string{"amount": "15000"}, true},
		{`var(amount) > 10000`, map[string]string{"amount": "5000"}, false},
		{`var(amount) >= 5000`, map[string]string{"amount": "5000"}, true},
		{`var(amount) < 100`, map[string]string{"amount": "50"}, true},
		{`var(amount) <= 100`, map[string]string{"amount": "100"}, true},
		{`var(escalate) == "true"`, map[string]string{"escalate": "true"}, true},
		{`var(has_nda)`, map[string]string{"has_nda": "true"}, true},
		{`var(has_nda)`, map[string]string{"has_nda": "false"}, false},
		{`var(has_nda)`, map[string]string{}, false}, // empty → false
		{`var(country) == "SE" && var(amount) > 5000`,
			map[string]string{"country": "SE", "amount": "10000"}, true},
		{`var(country) == "DE" || var(country) == "SE"`,
			map[string]string{"country": "SE"}, true},
		{`var(country) == "DE" || var(country) == "FR"`,
			map[string]string{"country": "SE"}, false},
		{``, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			if got := EvalCondition(tc.expr, tc.vars); got != tc.want {
				t.Errorf("EvalCondition(%q, %v) = %v, want %v", tc.expr, tc.vars, got, tc.want)
			}
		})
	}
}

// ── HTML render ───────────────────────────────────────────────────────────

func TestRenderHTML_HeadingAndParagraph(t *testing.T) {
	tree := &Tree{
		Version: 1,
		Blocks: []Block{
			{ID: "h1", Type: TypeHeading, Attrs: map[string]any{"level": float64(1)}, Text: "Title"},
			{ID: "p1", Type: TypeParagraph, Text: "Hello {{name}}"},
		},
	}
	out := RenderHTML(tree, map[string]string{"name": "Tom"})
	if !strings.Contains(out, `<h1 data-block-id="h1">Title</h1>`) {
		t.Errorf("missing h1: %s", out)
	}
	if !strings.Contains(out, `<p data-block-id="p1">Hello Tom</p>`) {
		t.Errorf("missing or unsubstituted paragraph: %s", out)
	}
}

func TestRenderHTML_SignatureField(t *testing.T) {
	tree := &Tree{
		Version: 1,
		Blocks: []Block{{
			ID:    "sig",
			Type:  TypeSignatureField,
			Attrs: map[string]any{"recipient_role": "client", "label": "Client signature"},
		}},
	}
	out := RenderHTML(tree, nil)
	if !strings.Contains(out, `data-recipient-role="client"`) {
		t.Errorf("missing recipient role: %s", out)
	}
	if !strings.Contains(out, `data-field-type="signature_field"`) {
		t.Errorf("missing field type: %s", out)
	}
}

func TestRenderHTML_ConditionalDropped(t *testing.T) {
	tree := &Tree{
		Version: 1,
		Blocks: []Block{{
			Type:  TypeConditional,
			Attrs: map[string]any{"expression": `var(amount) > 100`},
			Content: []Block{
				{Type: TypeParagraph, Text: "Subject to board approval"},
			},
		}},
	}
	out1 := RenderHTML(tree, map[string]string{"amount": "50"})
	if strings.Contains(out1, "board approval") {
		t.Errorf("conditional should have hidden content: %s", out1)
	}
	out2 := RenderHTML(tree, map[string]string{"amount": "200"})
	if !strings.Contains(out2, "board approval") {
		t.Errorf("conditional should have shown content: %s", out2)
	}
}

func TestRenderHTML_EscapesUserInput(t *testing.T) {
	tree := &Tree{
		Version: 1,
		Blocks:  []Block{{ID: "p", Type: TypeParagraph, Text: `<script>alert("xss")</script>`}},
	}
	out := RenderHTML(tree, nil)
	if strings.Contains(out, "<script>") {
		t.Errorf("script tag survived escaping: %s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("escaped form missing: %s", out)
	}
}

// ── Markdown round-trip ───────────────────────────────────────────────────

func TestParseMarkdown_HeadingsAndLists(t *testing.T) {
	src := `# Main title

A paragraph with **emphasis** in the source.

- bullet one
- bullet two

1. step one
2. step two
`
	tree := ParseMarkdown(src)
	if len(tree.Blocks) < 4 {
		t.Fatalf("expected at least 4 blocks, got %d", len(tree.Blocks))
	}
	if tree.Blocks[0].Type != TypeHeading || tree.Blocks[0].HeadingLevel() != 1 {
		t.Errorf("first block not h1: %+v", tree.Blocks[0])
	}
	foundUL := false
	foundOL := false
	for _, b := range tree.Blocks {
		if b.Type == TypeBulletList && len(b.Content) == 2 {
			foundUL = true
		}
		if b.Type == TypeOrderedList && len(b.Content) == 2 {
			foundOL = true
		}
	}
	if !foundUL {
		t.Error("missing bullet list")
	}
	if !foundOL {
		t.Error("missing ordered list")
	}
}

func TestParseMarkdown_Table(t *testing.T) {
	src := `| Item | Amount |
| --- | --- |
| Monthly fee | €8000 |
| Setup fee | €0 |
`
	tree := ParseMarkdown(src)
	if len(tree.Blocks) != 1 || tree.Blocks[0].Type != TypeTable {
		t.Fatalf("expected single table block, got %+v", tree.Blocks)
	}
	tbl := tree.Blocks[0]
	if len(tbl.Rows) != 2 {
		t.Errorf("expected 2 rows, got %d", len(tbl.Rows))
	}
}

func TestRenderMarkdownRoundTrip_PreservesHeadings(t *testing.T) {
	src := "# Hello\n\nWorld\n"
	tree := ParseMarkdown(src)
	rendered := RenderMarkdown(tree, nil)
	if !strings.Contains(rendered, "# Hello") {
		t.Errorf("heading lost in round-trip: %q", rendered)
	}
	if !strings.Contains(rendered, "World") {
		t.Errorf("paragraph lost in round-trip: %q", rendered)
	}
}

// ── HTML parser ───────────────────────────────────────────────────────────

func TestParseHTML_HeadingsAndParagraph(t *testing.T) {
	src := `<h2>Section</h2><p>Body text.</p>`
	tree := ParseHTML(src)
	if len(tree.Blocks) != 2 {
		t.Fatalf("expected 2 blocks, got %d (%+v)", len(tree.Blocks), tree.Blocks)
	}
	if tree.Blocks[0].Type != TypeHeading || tree.Blocks[0].HeadingLevel() != 2 {
		t.Errorf("first block not h2: %+v", tree.Blocks[0])
	}
	if tree.Blocks[1].Type != TypeParagraph || tree.Blocks[1].Text != "Body text." {
		t.Errorf("second block wrong: %+v", tree.Blocks[1])
	}
}

func TestParseHTML_Lists(t *testing.T) {
	src := `<ul><li>one</li><li>two</li></ul>`
	tree := ParseHTML(src)
	if len(tree.Blocks) != 1 || tree.Blocks[0].Type != TypeBulletList {
		t.Fatalf("expected bullet_list, got %+v", tree.Blocks)
	}
	if len(tree.Blocks[0].Content) != 2 {
		t.Errorf("expected 2 list items, got %d", len(tree.Blocks[0].Content))
	}
}

func TestParseHTML_Table(t *testing.T) {
	src := `<table><thead><tr><th>Item</th><th>Amount</th></tr></thead>
<tbody><tr><td>Fee</td><td>€8000</td></tr></tbody></table>`
	tree := ParseHTML(src)
	if len(tree.Blocks) != 1 || tree.Blocks[0].Type != TypeTable {
		t.Fatalf("expected table, got %+v", tree.Blocks)
	}
	if len(tree.Blocks[0].Rows) != 1 {
		t.Errorf("expected 1 row, got %d", len(tree.Blocks[0].Rows))
	}
}

// ── JSON round-trip integrity ─────────────────────────────────────────────

func TestJSONRoundTrip(t *testing.T) {
	original := &Tree{
		Version: 1,
		Blocks: []Block{
			{ID: "a", Type: TypeHeading, Attrs: map[string]any{"level": float64(2)}, Text: "Title"},
			{ID: "b", Type: TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}},
		},
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseTree(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Blocks) != len(original.Blocks) {
		t.Fatalf("block count mismatch")
	}
	if got.Blocks[1].AttrString("recipient_role", "") != "signer" {
		t.Errorf("recipient_role lost in round trip")
	}
}
