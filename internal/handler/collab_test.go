package handler

import (
	"reflect"
	"testing"
)

func TestCollabOriginPatterns_ProductionLocksToConfiguredHost(t *testing.T) {
	got := collabOriginPatterns("https://hash.brightinteraction.com")
	want := []string{"hash.brightinteraction.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prod origin: got %v, want %v", got, want)
	}
}

func TestCollabOriginPatterns_LocalDevExpandsLoopback(t *testing.T) {
	got := collabOriginPatterns("http://localhost:8090")
	// Local dev MUST include the localhost variants so the SvelteKit dev
	// server (port 5173) can still join. The first entry is always the
	// configured host so production stays first-match.
	if got[0] != "localhost:8090" {
		t.Errorf("first pattern should be the configured host, got %q", got[0])
	}
	for _, marker := range []string{"localhost", "localhost:*", "127.0.0.1", "[::1]"} {
		var found bool
		for _, p := range got {
			if p == marker {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("local dev origin patterns missing %q (got %v)", marker, got)
		}
	}
}

func TestCollabOriginPatterns_EmptyURLFallsBackToLoopback(t *testing.T) {
	got := collabOriginPatterns("")
	if len(got) == 0 || got[0] != "localhost" {
		t.Errorf("empty URL should default to localhost-only, got %v", got)
	}
}

func TestCollabOriginPatterns_RejectsForeignOrigin(t *testing.T) {
	// nhooyr's matcher is hostname-only and our allow-list is just
	// hash.brightinteraction.com in prod, so an attacker's host
	// like 'evil.example' would not match. We assert by inspecting the
	// list rather than by exercising nhooyr internals.
	got := collabOriginPatterns("https://hash.brightinteraction.com")
	for _, host := range []string{"evil.example", "localhost", "127.0.0.1"} {
		for _, allow := range got {
			if allow == host {
				t.Errorf("production allow-list should reject %q, but contains it", host)
			}
		}
	}
}

func TestCollabHost(t *testing.T) {
	cases := map[string]string{
		"https://hash.brightinteraction.com":     "hash.brightinteraction.com",
		"http://localhost:8090":                     "localhost:8090",
		"http://127.0.0.1":                          "127.0.0.1",
		"":                                          "",
		"not-a-url":                                 "",
		"http://[::1]:8080/sub/path":                "[::1]:8080",
	}
	for in, want := range cases {
		if got := collabHost(in); got != want {
			t.Errorf("collabHost(%q) = %q, want %q", in, got, want)
		}
	}
}
