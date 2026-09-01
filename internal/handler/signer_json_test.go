// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeSignerJSONRequiresOneUnambiguousObject(t *testing.T) {
	type input struct {
		Reason string `json:"reason"`
	}
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "valid", body: `{"reason":"first"}`, want: "first"},
		{name: "nested valid", body: `{"reason":"first"}`, want: "first"},
		{name: "paired surrogate", body: `{"reason":"\uD83D\uDCA1"}`, want: string(rune(0x1F4A1))},
		{name: "escaped backslash", body: `{"reason":"\\uD800"}`, want: `\uD800`},
		{name: "lone high surrogate", body: `{"reason":"\uD800"}`},
		{name: "lone low surrogate", body: `{"reason":"\uDFFF"}`},
		{name: "high then non-low", body: `{"reason":"\uD800\u0041"}`},
		{name: "high then escaped backslash", body: `{"reason":"\uD800\\uDC00"}`},
		{name: "duplicate", body: `{"reason":"first","reason":"last"}`},
		{name: "case alias", body: `{"REASON":"last"}`},
		{name: "case-variant duplicate", body: `{"reason":"first","REASON":"last"}`},
		{name: "trailing object", body: `{"reason":"first"}{"reason":"last"}`},
		{name: "unknown field", body: `{"reason":"first","ignored":true}`},
		{name: "empty", body: ``},
		{name: "array", body: `[]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/sign/token/decline", strings.NewReader(tt.body))
			var got input
			err := decodeSignerJSON(req, &got)
			if tt.want == "" {
				if err == nil {
					t.Fatalf("ambiguous body was accepted as %#v", got)
				}
				return
			}
			if err != nil || got.Reason != tt.want {
				t.Fatalf("decode = %#v, %v; want reason %q", got, err, tt.want)
			}
		})
	}
}

func TestDecodeSignerJSONRejectsInvalidUTF8(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/sign/token/decline", strings.NewReader("{\"reason\":\"\xff\"}"))
	var got struct {
		Reason string `json:"reason"`
	}
	if err := decodeSignerJSON(req, &got); err == nil {
		t.Fatal("invalid UTF-8 JSON was accepted")
	}
}

func TestDecodeSignerJSONDoesNotReflectUnknownFieldNames(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"reason":"valid","attacker@example.test":"secret"}`))
	var got struct {
		Reason string `json:"reason"`
	}
	err := decodeSignerJSON(req, &got)
	if err == nil || strings.Contains(err.Error(), "attacker@example.test") {
		t.Fatalf("unsafe parser error: %v", err)
	}
}
