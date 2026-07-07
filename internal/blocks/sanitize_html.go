package blocks

import (
	"regexp"

	"github.com/microcosm-cc/bluemonday"
)

// rawHTMLPolicy allowlists raw_html block content at the render boundary. It
// strips <script>, every on* event handler, javascript: URIs,
// <iframe>/<object>/<embed>, and inline style attributes, while preserving the
// document-body markup users legitimately author.
//
// It must also preserve the signature span the signing flow injects through the
// same TypeRawHTML path: <span class="hash-signature" data-font="Caveat">.
// The data-font attribute drives the cursive-font CSS selector
// (.hash-signature[data-font="..."]), so span + class + data-font are
// explicitly allowed. None of these can execute script, so the security
// properties hold.
var rawHTMLPolicy = func() *bluemonday.Policy {
	p := bluemonday.UGCPolicy()
	p.AllowElements("span")
	p.AllowAttrs("class").OnElements(
		"span", "div", "p", "table", "thead", "tbody", "tr", "td", "th",
		"ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "code", "pre", "a",
	)
	p.AllowAttrs("data-font").OnElements("span")
	// SSRF hardening (part 1): allow relative URLs so legitimate in-app paths
	// (e.g. /api/v1/storage/...) survive; absolute + protocol-relative URLs are
	// stripped afterwards in SanitizeRawHTML. (bluemonday's UGCPolicy allows
	// http/https and its allowed-scheme set cannot be un-set, so the block has
	// to happen post-sanitize.)
	p.AllowRelativeURLs(true)
	p.RequireNoFollowOnLinks(true)
	return p
}()

// remoteResourceURL matches a URL-bearing attribute whose value is absolute
// (scheme://host) or protocol-relative (//host).
var remoteResourceURL = regexp.MustCompile(`(?i)\s(?:src|href|srcset|poster|background|cite|data|formaction|xlink:href)\s*=\s*["'](?:[a-z][a-z0-9+.-]*:)?//[^"']*["']`)

// SanitizeRawHTML allowlist-sanitises a raw HTML fragment. Applied at the
// single render chokepoint so it covers the signer page, the signed PDF, and
// any pre-existing stored blocks.
//
// After bluemonday strips script/on*/iframe/javascript:, a second pass drops
// absolute + protocol-relative resource URLs. raw_html is rendered to PDF by
// Chromium, which auto-fetches <img src>; a remote/internal URL there is an
// SSRF (cloud metadata, minio, internal services). Removing the attribute
// removes the fetch, leaving relative in-app paths intact. Defense-in-depth:
// prod Gotenberg also runs with a --chromium-deny-list (docker-compose.prod.yml).
func SanitizeRawHTML(s string) string {
	return remoteResourceURL.ReplaceAllString(rawHTMLPolicy.Sanitize(s), "")
}
