package render

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsValidFont(t *testing.T) {
	for _, f := range SupportedFonts {
		if !IsValidFont(f) {
			t.Errorf("supported font %q rejected", f)
		}
	}
	if IsValidFont("Comic Sans MS") {
		t.Error("Comic Sans accepted; allowlist broken")
	}
	if IsValidFont("") {
		t.Error("empty accepted")
	}
}

func TestRenderSignatureSpan(t *testing.T) {
	out := RenderSignatureSpan("Tom Isgren", "Caveat")
	for _, want := range []string{`data-font="Caveat"`, "Tom Isgren", "hash-signature"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q: %s", want, out)
		}
	}
}

func TestRenderSignatureSpan_FallsBackOnUnknownFont(t *testing.T) {
	out := RenderSignatureSpan("Tom", "Comic Sans")
	if !strings.Contains(out, `data-font="Caveat"`) {
		t.Errorf("unknown font should fall back to Caveat: %s", out)
	}
}

func TestRenderSignatureSpan_EscapesName(t *testing.T) {
	out := RenderSignatureSpan(`<script>alert(1)</script>`, "Caveat")
	if strings.Contains(out, "<script>") {
		t.Errorf("script tag survived escape: %s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("expected escaped form: %s", out)
	}
}

func TestSignatureCSS_DeclaresAllFontsLocally(t *testing.T) {
	css := SignatureCSS()
	wantFiles := []string{
		"Caveat.woff2",
		"DancingScript.woff2",
		"GreatVibes.woff2",
		"Sacramento.woff2",
		"HomemadeApple.woff2",
		"Inter.woff2",
		"Geist.woff2",
	}
	for _, f := range wantFiles {
		if !strings.Contains(css, f) {
			t.Errorf("CSS missing @font-face for %q", f)
		}
	}
	if strings.Contains(css, "googleapis.com") || strings.Contains(css, "gstatic.com") {
		t.Error("CSS still references third-party font CDN; fonts must be self-hosted")
	}
	for _, f := range SupportedFonts {
		if !strings.Contains(css, "'"+f+"'") {
			t.Errorf("CSS missing font-family declaration for %q", f)
		}
	}
}

func TestFontAssets_AllNonEmpty(t *testing.T) {
	got := FontAssets()
	if len(got) < len(SupportedFonts) {
		t.Fatalf("FontAssets returned %d, want >= %d", len(got), len(SupportedFonts))
	}
	for _, a := range got {
		if a.Filename == "" {
			t.Errorf("font asset missing filename")
		}
		if len(a.Bytes) < 1024 {
			t.Errorf("font %q suspiciously small: %d bytes", a.Filename, len(a.Bytes))
		}
		if string(a.Bytes[:4]) != "wOF2" {
			t.Errorf("font %q missing woff2 magic; got %q", a.Filename, string(a.Bytes[:4]))
		}
	}
}

func TestGotenberg_RetriesOnTransientFailure(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("chromium pool exhausted"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("%PDF-1.7 ok"))
	}))
	defer srv.Close()
	g := NewGotenberg(srv.URL)
	out, err := g.HTMLToPDF(context.Background(), "<html></html>", PDFOptions{})
	if err != nil {
		t.Fatalf("retry should recover from 2x 503: %v", err)
	}
	if !strings.HasPrefix(string(out), "%PDF") {
		t.Errorf("expected PDF bytes, got %q", string(out))
	}
	if attempts != 3 {
		t.Errorf("expected exactly 3 attempts, got %d", attempts)
	}
}

func TestGotenberg_DoesNotRetryOn4xx(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad input"))
	}))
	defer srv.Close()
	g := NewGotenberg(srv.URL)
	_, err := g.HTMLToPDF(context.Background(), "<html></html>", PDFOptions{})
	if err == nil {
		t.Fatal("expected error on 400")
	}
	if attempts != 1 {
		t.Errorf("4xx should not retry; got %d attempts", attempts)
	}
}

func TestGotenberg_PingOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("expected /health, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	g := NewGotenberg(srv.URL)
	if err := g.Ping(context.Background()); err != nil {
		t.Errorf("ping should succeed: %v", err)
	}
}

func TestNewGotenberg_NormalizesURL(t *testing.T) {
	g := NewGotenberg("http://gotenberg:3000/")
	if g.BaseURL != "http://gotenberg:3000" {
		t.Errorf("trailing slash not stripped: %q", g.BaseURL)
	}
}
