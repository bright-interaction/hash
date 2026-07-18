// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/brightinteraction/hash/internal/blocks"
)

func testCtx() context.Context { return context.Background() }
func testUUID() uuid.UUID      { return uuid.New() }

func TestVarsFromJSON(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
		want map[string]string
	}{
		{"empty", nil, map[string]string{}},
		{"strings only", json.RawMessage(`{"a":"x","b":"y"}`), map[string]string{"a": "x", "b": "y"}},
		{"mixed types coerced", json.RawMessage(`{"n":42,"b":true}`), map[string]string{"n": "42", "b": "true"}},
		{"non-scalar dropped", json.RawMessage(`{"keep":"yes","drop":[1,2,3]}`), map[string]string{"keep": "yes"}},
		{"malformed returns empty", json.RawMessage(`not-json`), map[string]string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := varsFromJSON(tc.raw)
			if len(got) != len(tc.want) {
				t.Errorf("size mismatch got=%v want=%v", got, tc.want)
				return
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("vars[%q]=%q want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestFindSignatureFieldFor_RoleMatch(t *testing.T) {
	tree := &blocks.Tree{Version: 1, Blocks: []blocks.Block{
		{ID: "p", Type: blocks.TypeParagraph, Text: "x"},
		{ID: "sig-client", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "client"}},
		{ID: "sig-provider", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "provider"}},
	}}
	got := findSignatureFieldFor(tree, "client")
	if got == nil || got.ID != "sig-client" {
		t.Errorf("client mismatch: %+v", got)
	}
	got = findSignatureFieldFor(tree, "provider")
	if got == nil || got.ID != "sig-provider" {
		t.Errorf("provider mismatch: %+v", got)
	}
}

func TestFindSignatureFieldFor_NoMatch(t *testing.T) {
	tree := &blocks.Tree{Version: 1, Blocks: []blocks.Block{
		{ID: "p", Type: blocks.TypeParagraph, Text: "no fields here"},
	}}
	if got := findSignatureFieldFor(tree, "client"); got != nil {
		t.Errorf("expected nil; got %+v", got)
	}
}

func TestFindSignatureFieldFor_FallsBackToFirstUnboundField(t *testing.T) {
	tree := &blocks.Tree{Version: 1, Blocks: []blocks.Block{
		{ID: "sig-any", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": ""}},
	}}
	got := findSignatureFieldFor(tree, "anything")
	if got == nil || got.ID != "sig-any" {
		t.Errorf("empty role should match anything; got %+v", got)
	}
}

func TestBuildHTMLDocument_IncludesSignatureCSS(t *testing.T) {
	out := buildHTMLDocument("", "<p>hi</p>", "<p>cert</p>")
	for _, want := range []string{
		"<!doctype html>",
		"hash-signature",
		"<p>hi</p>",
		"<p>cert</p>",
		"Caveat.woff2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if strings.Contains(out, "googleapis.com") || strings.Contains(out, "gstatic.com") {
		t.Error("rendered HTML still references third-party font CDN")
	}
}

func TestHtmlEscape(t *testing.T) {
	if got := htmlEscape(`<a href="x">&amp;</a>`); got != "&lt;a href=&quot;x&quot;&gt;&amp;amp;&lt;/a&gt;" {
		t.Errorf("unexpected escape: %q", got)
	}
}

func TestTextOrNull(t *testing.T) {
	if v := textOrNull(""); v.Valid {
		t.Error("empty should be invalid")
	}
	if v := textOrNull("x"); !v.Valid || v.String != "x" {
		t.Errorf("non-empty wrong: %+v", v)
	}
}

func TestTruncateFieldValueForCert(t *testing.T) {
	short := "hello"
	if got := truncateFieldValueForCert(short); got != short {
		t.Errorf("short value should not be truncated: %q", got)
	}
	long := strings.Repeat("x", 250)
	got := truncateFieldValueForCert(long)
	if !strings.HasSuffix(got, "[truncated, full value in document_fields]") {
		t.Errorf("expected truncation marker, got %q", got)
	}
	if len(got) > 260 {
		t.Errorf("truncated too long: %d chars", len(got))
	}
}

func TestRenderFieldValuesSection_NilQueriesReturnsEmpty(t *testing.T) {
	if got := renderFieldValuesSection(testCtx(), nil, testUUID()); got != "" {
		t.Errorf("nil queries should yield empty; got %q", got)
	}
}
