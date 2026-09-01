// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package resolver

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type fakeDoer struct {
	resp *http.Response
	err  error
	last *http.Request
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	f.last = req
	return f.resp, f.err
}

func mkResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func TestHTTPSource_NotConfigured(t *testing.T) {
	src := NewCRMDealSource("", "")
	_, err := src.Fetch(context.Background(), Ref{Source: "deal_1"})
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}
}

func TestHTTPSource_HappyPath(t *testing.T) {
	doer := &fakeDoer{resp: mkResp(200, `{"deal":{"amount":42000,"name":"Acme MSA"}}`)}
	src := NewCRMDealSource("https://crm.test", "tok-abc")
	src.Client = doer

	val, err := src.Fetch(context.Background(), Ref{
		Source: "deal_1",
		Path:   "deal.amount",
	})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if val != "42000" {
		t.Fatalf("want 42000, got %q", val)
	}
	if got := doer.last.URL.Path; got != "/api/v1/deals/deal_1" {
		t.Fatalf("wrong url path %q", got)
	}
	if got := doer.last.Header.Get("Authorization"); got != "Bearer tok-abc" {
		t.Fatalf("wrong auth header %q", got)
	}
}

func TestHTTPSource_RejectsPathAndQueryInjectionBeforeSendingBearerToken(t *testing.T) {
	for _, sourceRef := range []string{
		"../admin",
		"deal_1?include=secrets",
		"deal_1#fragment",
		"deal_1%2fadmin",
		"deal_1\\admin",
		strings.Repeat("a", 257),
	} {
		t.Run(sourceRef, func(t *testing.T) {
			doer := &fakeDoer{resp: mkResp(200, `{}`)}
			src := NewCRMDealSource("https://crm.test", "tok-abc")
			src.Client = doer
			if _, err := src.Fetch(context.Background(), Ref{Source: sourceRef}); err == nil {
				t.Fatalf("unsafe source_ref %q was accepted", sourceRef)
			}
			if doer.last != nil {
				t.Fatalf("request was sent for unsafe source_ref %q", sourceRef)
			}
		})
	}
}

func TestHTTPSource_404IsErrNotFound(t *testing.T) {
	doer := &fakeDoer{resp: mkResp(404, `{}`)}
	src := NewCRMContactSource("https://crm.test", "tok")
	src.Client = doer

	_, err := src.Fetch(context.Background(), Ref{Source: "contact_x", Path: "name"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestHTTPSource_PathMissing(t *testing.T) {
	doer := &fakeDoer{resp: mkResp(200, `{"deal":{"name":"x"}}`)}
	src := NewCRMDealSource("https://crm.test", "tok")
	src.Client = doer

	_, err := src.Fetch(context.Background(), Ref{Source: "deal_1", Path: "deal.amount"})
	if err == nil || !strings.Contains(err.Error(), "path") {
		t.Fatalf("want path-not-found error, got %v", err)
	}
}

func TestHTTPSource_ServerError(t *testing.T) {
	doer := &fakeDoer{resp: mkResp(500, "boom")}
	src := NewScannerFindingSource("https://svar.test", "tok")
	src.Client = doer

	_, err := src.Fetch(context.Background(), Ref{Source: "scan_1", Path: "summary.critical_count"})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("want 5xx error, got %v", err)
	}
}

func TestJSONPathLookup_NestedAndArray(t *testing.T) {
	root := map[string]any{
		"deal": map[string]any{
			"amount": float64(42),
			"items": []any{
				map[string]any{"sku": "A"},
				map[string]any{"sku": "B"},
			},
		},
	}
	cases := []struct {
		path string
		want string
		ok   bool
	}{
		{"deal.amount", "42", true},
		{"deal.items.1.sku", "B", true},
		{"deal.items.5.sku", "", false},
		{"missing", "", false},
		{"", "", true}, // empty path returns root
	}
	for _, c := range cases {
		got, ok := jsonPathLookup(root, c.path)
		if ok != c.ok {
			t.Errorf("path %q: ok=%v want %v", c.path, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if c.path == "" {
			continue // root is a map, can't compare to want
		}
		s, _ := stringify(got)
		if s != c.want {
			t.Errorf("path %q: got %q want %q", c.path, s, c.want)
		}
	}
}

func TestStringify(t *testing.T) {
	cases := []struct {
		in   any
		want string
		ok   bool
	}{
		{"hello", "hello", true},
		{float64(42), "42", true},
		{float64(3.14), "3.14", true},
		{true, "true", true},
		{false, "false", true},
		{nil, "", false},
		{map[string]any{"a": 1}, `{"a":1}`, true},
	}
	for _, c := range cases {
		got, ok := stringify(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("stringify(%v): got (%q,%v) want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
