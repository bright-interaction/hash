// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// The proposal-render sanitizer keeps a page's own design (its <style>, inline
// CSS, layout, and data: URIs) while removing the JS execution + remote-fetch
// surface, so an author-supplied "designed proposal" can be rendered to a
// signable PDF by Gotenberg's headless Chromium without becoming an SSRF or
// script-exfiltration primitive. It is deliberately NOT bluemonday
// (blocks.SanitizeRawHTML): UGC sanitization strips <style>/inline CSS and
// would destroy the design, which is the entire point of this path.
var (
	reScriptBlock  = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>`)
	reScriptStray  = regexp.MustCompile(`(?is)</?script\b[^>]*>`)
	reDangerTags   = regexp.MustCompile(`(?is)</?(?:iframe|object|embed|link|base|applet)\b[^>]*>`)
	reMetaRefresh  = regexp.MustCompile(`(?is)<meta\b[^>]*http-equiv\s*=\s*["']?\s*refresh[^>]*>`)
	reOnHandler    = regexp.MustCompile(`(?i)(^|[\s"'/])on[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	reCSSRemoteURL = regexp.MustCompile(`(?i)url\(\s*['"]?\s*(?:[a-z][a-z0-9+.-]*:)?//[^)]*\)`)
	reCSSImport    = regexp.MustCompile(`(?i)@import[^;]*?(?:[a-z][a-z0-9+.-]*:)?//[^;]*;`)
	// reRemoteURLValue matches a resource value that resolves to a network fetch:
	// an optional scheme followed by a `//` authority (http://, https://, ftp://,
	// file://, and protocol-relative //). data:, mailto:, tel:, fragments, and
	// relative paths do NOT match, matching the prior regex's semantics - but it
	// is tested against the ENTITY-DECODED, whitespace-stripped value the HTML
	// parser produces, so `src=http://x` (unquoted), `src=" http://x"` (leading
	// space), and `src="&#104;ttp://x"` (entity-encoded) can no longer evade it.
	reRemoteURLValue = regexp.MustCompile(`^(?:[a-z][a-z0-9+.-]*:)?//`)
)

// resourceAttrs are the attributes Chromium may dereference during a headless
// render (issuing a network GET). A remote value in any of these is stripped.
var resourceAttrs = map[string]bool{
	"src": true, "href": true, "srcset": true, "poster": true,
	"background": true, "cite": true, "data": true, "formaction": true,
	"action": true, "xlink:href": true,
}

// SanitizeForRender prepares author-supplied HTML for hermetic Gotenberg
// (Chromium) rendering to a proposal PDF. It KEEPS the page's own styling,
// layout, and data: URIs, and removes only:
//
//   - <script> blocks + stray script tags (a static PDF needs no JS)
//   - on* inline event handlers
//   - <iframe>/<object>/<embed>/<link>/<base>/<applet> + <meta http-equiv=refresh>
//   - every REMOTE (http/https/protocol-relative/other-`//`) URL in a resource
//     attribute or in CSS url()/@import, so Chromium cannot be steered to fetch
//     cloud metadata, MinIO, or any internal host (SSRF). data: URIs + relative
//     paths survive.
//
// The remote-resource-attribute pass parses the HTML (golang.org/x/net/html)
// rather than regex-matching it, so unquoted, leading-whitespace, and
// entity-encoded values that a quote-anchored regex missed are normalized and
// caught. Defense-in-depth: prod Gotenberg also runs with a --chromium-deny-list
// (docker-compose.prod.yml) so remote fetches are blocked at the network layer
// even if a reference slips past these passes.
func SanitizeForRender(rawHTML string) string {
	rawHTML = reScriptBlock.ReplaceAllString(rawHTML, "")
	rawHTML = reScriptStray.ReplaceAllString(rawHTML, "")
	rawHTML = reDangerTags.ReplaceAllString(rawHTML, "")
	rawHTML = reMetaRefresh.ReplaceAllString(rawHTML, "")
	rawHTML = reOnHandler.ReplaceAllString(rawHTML, "$1")
	rawHTML = stripRemoteResourceAttrs(rawHTML)
	rawHTML = reCSSRemoteURL.ReplaceAllString(rawHTML, "url(about:blank)")
	rawHTML = reCSSImport.ReplaceAllString(rawHTML, "")
	return rawHTML
}

// stripRemoteResourceAttrs tokenizes the HTML and drops any resource attribute
// whose value (entity-decoded + whitespace-stripped, the way Chromium reads it)
// resolves to a remote fetch. Only tags that actually carry such an attribute
// are reserialized; every other token (text, <style> rawtext, comments, the
// doctype) is written back byte-for-byte, so the author's design is preserved.
func stripRemoteResourceAttrs(input string) string {
	z := html.NewTokenizer(strings.NewReader(input))
	var b strings.Builder
	b.Grow(len(input))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			// io.EOF (the normal terminator) or a read error: emit whatever raw
			// bytes remain for this token and stop.
			b.Write(z.Raw())
			return b.String()
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			b.Write(z.Raw())
			continue
		}
		raw := append([]byte(nil), z.Raw()...) // Raw is only valid until the next Next()
		name, hasAttr := z.TagName()
		if !hasAttr {
			b.Write(raw)
			continue
		}
		type attr struct{ k, v string }
		var kept []attr
		dropped := false
		for {
			k, v, more := z.TagAttr()
			key := strings.ToLower(string(k))
			if resourceAttrs[key] && isRemoteURLValue(string(v)) {
				dropped = true
			} else {
				kept = append(kept, attr{string(k), string(v)})
			}
			if !more {
				break
			}
		}
		if !dropped {
			b.Write(raw)
			continue
		}
		b.WriteByte('<')
		b.Write(name)
		for _, a := range kept {
			b.WriteByte(' ')
			b.WriteString(a.k)
			b.WriteString(`="`)
			b.WriteString(html.EscapeString(a.v))
			b.WriteByte('"')
		}
		if tt == html.SelfClosingTagToken {
			b.WriteString(" /")
		}
		b.WriteByte('>')
	}
}

// isRemoteURLValue reports whether an attribute value would drive Chromium to
// fetch a remote resource. Chromium strips leading/trailing and internal ASCII
// whitespace + control characters from URL attributes, so we do the same before
// testing the scheme, defeating `src=" http://x"` and `src="ht\ttp://x"` style
// evasions. The value is already entity-decoded by the HTML tokenizer.
func isRemoteURLValue(v string) bool {
	cleaned := strings.Map(func(r rune) rune {
		if r <= 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
	return reRemoteURLValue.MatchString(strings.ToLower(cleaned))
}
