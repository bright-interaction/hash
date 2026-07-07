package blocks

import "github.com/microcosm-cc/bluemonday"

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
	return p
}()

// SanitizeRawHTML allowlist-sanitises a raw HTML fragment. Applied at the
// single render chokepoint so it covers the signer page, the signed PDF, and
// any pre-existing stored blocks.
func SanitizeRawHTML(s string) string {
	return rawHTMLPolicy.Sanitize(s)
}
