// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"strings"
)

//go:embed all:frontend/build
var frontendFS embed.FS

var inlineScriptRe = regexp.MustCompile(`(?s)<script\b([^>]*)>(.*?)</script>`)

// frontendScriptCSP returns the script-src CSP additions (sha256 hashes) for the
// SvelteKit inline bootstrap script(s) in the embedded shell. The strict
// script-src 'self' CSP blocks inline scripts, which would leave the whole SPA
// blank; hashing the exact bootstrap content allows just that script with no
// 'unsafe-inline'. Returns a string of leading-space-prefixed tokens (or "").
func frontendScriptCSP() string {
	data, err := frontendFS.ReadFile("frontend/build/index.html")
	if err != nil {
		return ""
	}
	var b strings.Builder
	for _, m := range inlineScriptRe.FindAllSubmatch(data, -1) {
		if strings.Contains(strings.ToLower(string(m[1])), "src=") {
			continue // external script; 'self' already covers it
		}
		sum := sha256.Sum256(m[2]) // browsers hash the exact text content
		b.WriteString(" 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'")
	}
	return b.String()
}

// frontendHandler returns an http.Handler that serves the embedded
// SvelteKit static build. It falls back to index.html for any path that
// doesn't match a real file, so the SPA's client-side router handles
// /verify, /legal/*, /dashboard/*, /sign/[token]/*, etc.
//
// API routes are mounted before this handler in the chi tree so /api/v1,
// /mcp, /sign, /auth, /health, /e/o, /.well-known/* all win first.
func frontendHandler() http.Handler {
	sub, err := fs.Sub(frontendFS, "frontend/build")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "frontend not embedded", http.StatusInternalServerError)
		})
	}

	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean(r.URL.Path)
		// Strip leading slash for fs.FS lookup. Treat / as the SPA root.
		lookup := strings.TrimPrefix(clean, "/")
		if lookup == "" || lookup == "." {
			serveFallback(w, r, sub)
			return
		}

		// If the file exists in the embedded FS, serve it directly.
		if f, err := sub.Open(lookup); err == nil {
			info, statErr := f.Stat()
			f.Close()
			if statErr == nil && !info.IsDir() {
				// Set conservative cache headers; the SvelteKit build hashes
				// asset filenames so we can cache aggressively.
				switch {
				case strings.HasPrefix(clean, "/_app/"):
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				case strings.HasPrefix(clean, "/fonts/") && strings.HasSuffix(clean, ".woff2"):
					// Font filenames are content-hashed by upstream; safe to
					// freeze for a year. Avoids re-downloading 800 KB on every
					// pageload behind a private CDN.
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
					w.Header().Set("Access-Control-Allow-Origin", "*")
				default:
					w.Header().Set("Cache-Control", "public, max-age=300")
				}
				fileServer.ServeHTTP(w, r)
				return
			}
		}

		// SPA fallback: serve index.html for any unknown route. The
		// SvelteKit client-side router handles the rest.
		serveFallback(w, r, sub)
	})
}

func serveFallback(w http.ResponseWriter, r *http.Request, sub fs.FS) {
	f, err := sub.Open("index.html")
	if err != nil {
		// Build artifact missing. Return a friendly hint rather than 500.
		if errors.Is(err, fs.ErrNotExist) {
			http.Error(w, "frontend build missing; run `bun run build` then rebuild the image", http.StatusInternalServerError)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = io.Copy(w, f)
}
