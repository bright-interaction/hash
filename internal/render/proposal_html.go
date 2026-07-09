package render

import "regexp"

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
	reRemoteAttr   = regexp.MustCompile(`(?i)\s(?:src|href|srcset|poster|background|cite|data|formaction|action|xlink:href)\s*=\s*["'](?:[a-z][a-z0-9+.-]*:)?//[^"']*["']`)
	reCSSRemoteURL = regexp.MustCompile(`(?i)url\(\s*['"]?\s*(?:[a-z][a-z0-9+.-]*:)?//[^)]*\)`)
	reCSSImport    = regexp.MustCompile(`(?i)@import[^;]*?(?:[a-z][a-z0-9+.-]*:)?//[^;]*;`)
)

// SanitizeForRender prepares author-supplied HTML for hermetic Gotenberg
// (Chromium) rendering to a proposal PDF. It KEEPS the page's own styling,
// layout, and data: URIs, and removes only:
//
//   - <script> blocks + stray script tags (a static PDF needs no JS)
//   - on* inline event handlers
//   - <iframe>/<object>/<embed>/<link>/<base>/<applet> + <meta http-equiv=refresh>
//   - every REMOTE (http/https/protocol-relative) URL in a resource attribute
//     or in CSS url()/@import, so Chromium cannot be steered to fetch cloud
//     metadata, MinIO, or any internal host (SSRF). data: URIs + relative
//     paths survive.
//
// Defense-in-depth: prod Gotenberg also runs with a --chromium-deny-list
// (docker-compose.prod.yml), so private-IP fetches are blocked at the network
// layer even if a reference slips past these passes.
func SanitizeForRender(html string) string {
	html = reScriptBlock.ReplaceAllString(html, "")
	html = reScriptStray.ReplaceAllString(html, "")
	html = reDangerTags.ReplaceAllString(html, "")
	html = reMetaRefresh.ReplaceAllString(html, "")
	html = reOnHandler.ReplaceAllString(html, "$1")
	html = reRemoteAttr.ReplaceAllString(html, "")
	html = reCSSRemoteURL.ReplaceAllString(html, "url(about:blank)")
	html = reCSSImport.ReplaceAllString(html, "")
	return html
}
