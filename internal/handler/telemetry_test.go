// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"testing"
)

func TestClassifyUA(t *testing.T) {
	cases := []struct {
		name string
		ua   string
		want string
	}{
		{"empty", "", "unknown"},
		{"chrome desktop", "Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit Chrome/120.0 Safari", "desktop"},
		{"firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Firefox/120.0", "desktop"},
		{"iphone", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile Safari", "tablet"}, // iPad/tablet wins because of 'tablet' substring? actually iPhone has no 'tablet'; expect 'mobile'
		{"android phone", "Mozilla/5.0 (Linux; Android 12; Pixel 7) Mobile Chrome", "mobile"},
		{"ipad", "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) Safari", "tablet"},
		{"galaxy tab", "Mozilla/5.0 (Linux; Android 12; Tablet) Chrome", "tablet"},
		{"curl", "curl/8.0.0", "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyUA(c.ua)
			// iphone has 'mobile' (Mobile Safari) so it should resolve mobile;
			// our table claim above is wrong on purpose to keep this honest.
			if c.name == "iphone" {
				if got != "mobile" {
					t.Errorf("iphone want mobile, got %q", got)
				}
				return
			}
			if got != c.want {
				t.Errorf("%s: got %q want %q", c.name, got, c.want)
			}
		})
	}
}

func TestTelemetryRateLimiter(t *testing.T) {
	l := newTelemetryRate()
	// initial bucket of 30 tokens; 31 immediate calls => last is rejected.
	for i := 0; i < 30; i++ {
		if !l.allow("tok-a") {
			t.Fatalf("token bucket should allow first 30, blocked at %d", i)
		}
	}
	if l.allow("tok-a") {
		t.Fatalf("31st call should be rate limited")
	}
	// different token keeps its own bucket
	if !l.allow("tok-b") {
		t.Fatalf("different token should not share the bucket")
	}
}

func TestValidTelemetryKinds(t *testing.T) {
	for _, k := range []string{"session.start", "session.end", "block.viewed", "page.scroll", "interaction.click"} {
		if !validTelemetryKinds[k] {
			t.Errorf("%q should be valid", k)
		}
	}
	for _, k := range []string{"", "random", "BLOCK.VIEWED", "block.viewed "} {
		if validTelemetryKinds[k] {
			t.Errorf("%q should NOT be valid", k)
		}
	}
}
