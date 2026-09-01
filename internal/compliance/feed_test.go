// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package compliance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPFeedFetchesBoundedJSONWithoutFollowingRedirects(t *testing.T) {
	published := "2026-08-01T12:00:00Z"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/feed", http.StatusFound)
		case "/feed":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write([]byte(`{"items":[{"id":"edpb/real-1","title":"Guidance","summary":"Summary","topic":"lawful_basis","published_at":"` + published + `"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	feed := NewHTTPFeed(server.URL+"/feed", true)
	items, err := feed.Fetch(context.Background(), time.Time{})
	if err != nil || len(items) != 1 || items[0].ID != "edpb/real-1" {
		t.Fatalf("Fetch() = %#v, %v", items, err)
	}

	feed = NewHTTPFeed(server.URL+"/redirect", true)
	if _, err := feed.Fetch(context.Background(), time.Time{}); err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("credential/integrity redirect was followed: %v", err)
	}
}

func TestHTTPFeedRejectsOversizeAndWrongContentType(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contentType string
		body        string
		want        string
	}{
		{
			name:        "wrong content type",
			contentType: "text/html",
			body:        `{"items":[]}`,
			want:        "application/json",
		},
		{
			name:        "oversized response",
			contentType: "application/json",
			body:        `{"items":[]}` + strings.Repeat(" ", maxComplianceFeedBytes),
			want:        "exceeds",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			feed := NewHTTPFeed(server.URL, true)
			if _, err := feed.Fetch(context.Background(), time.Time{}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Fetch() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidateFeedItemBounds(t *testing.T) {
	valid := FeedItem{
		ID: "edpb/real-1", Title: "Guidance", Summary: "Summary",
		Topic: "lawful_basis", PublishedAt: time.Now().UTC(),
	}
	if err := validateFeedItem(valid); err != nil {
		t.Fatalf("valid item rejected: %v", err)
	}
	invalid := valid
	invalid.ID = " "
	if err := validateFeedItem(invalid); err == nil {
		t.Fatal("blank feed id accepted")
	}
	invalid = valid
	invalid.Summary = strings.Repeat("x", 64*1024+1)
	if err := validateFeedItem(invalid); err == nil {
		t.Fatal("oversized feed summary accepted")
	}
}
