// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"net/url"
	"regexp"
	"strconv"
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
	reDangerTags   = regexp.MustCompile(`(?is)</?(?:iframe|object|embed|link|base|applet|animate|animatemotion|animatetransform|set|discard)\b[^>]*>`)
	reMetaRefresh  = regexp.MustCompile(`(?is)<meta\b[^>]*http-equiv\s*=\s*["']?\s*refresh[^>]*>`)
	reOnHandler    = regexp.MustCompile(`(?i)(^|[\s"'/])on[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	reCSSImageSet  = regexp.MustCompile(`(?is)(?:-webkit-)?image-set\s*\([^)]*\)`)
	reCSSImageFunc = regexp.MustCompile(`(?is)\bimage\s*\([^)]*\)`)
	reStyleElement = regexp.MustCompile(`(?is)<style\b[^>]*>.*?</style\s*>`)
)

// resourceAttrs are the attributes Chromium may dereference during a headless
// render (issuing a network GET). A remote value in any of these is stripped.
var resourceAttrs = map[string]bool{
	"src": true, "href": true, "poster": true,
	"background": true, "cite": true, "data": true, "formaction": true,
	"action": true, "xlink:href": true, "xml:base": true,
}

// CSS presentation attributes can dereference url(...), especially inside SVG.
// Treating them like inline style closes <rect fill>, <filter>, <mask>, marker,
// and cursor variants without stripping ordinary colours or presentation rules.
var cssResourceAttrs = map[string]bool{
	"style": true, "fill": true, "stroke": true, "filter": true,
	"clip-path": true, "mask": true, "marker": true, "marker-start": true,
	"marker-mid": true, "marker-end": true, "cursor": true,
}

// SanitizeForRender prepares author-supplied HTML for hermetic Gotenberg
// (Chromium) rendering to a proposal PDF. It KEEPS the page's own styling,
// layout, and data: URIs, and removes only:
//
//   - <script> blocks + stray script tags (a static PDF needs no JS)
//   - on* inline event handlers
//   - <iframe>/<object>/<embed>/<link>/<base>/<applet>, SVG animation, and
//     <meta http-equiv=refresh>
//   - every network URL and every local-file reference (file:, absolute paths,
//     encoded/backslash variants, and parent traversal) in resource attributes,
//     SVG presentation attributes, CSS url(), and @import. Chromium therefore
//     cannot fetch metadata/MinIO (SSRF) or read Gotenberg container files (LFI).
//     data: URIs, fragments, and non-traversing workspace-relative paths survive.
//
// The resource-attribute pass parses the HTML (golang.org/x/net/html)
// rather than regex-matching it, so unquoted, leading-whitespace, and
// entity-encoded values that a quote-anchored regex missed are normalized and
// caught. Defense-in-depth: prod Gotenberg also denies private-network fetches.
// Gotenberg must retain access to its own file:///tmp entrypoint, so local-file
// isolation is enforced here on author-controlled references instead of through
// a global Chromium file-scheme deny that would also block index.html.
func SanitizeForRender(rawHTML string) string {
	rawHTML = reScriptBlock.ReplaceAllString(rawHTML, "")
	rawHTML = reScriptStray.ReplaceAllString(rawHTML, "")
	rawHTML = reDangerTags.ReplaceAllString(rawHTML, "")
	rawHTML = reMetaRefresh.ReplaceAllString(rawHTML, "")
	rawHTML = reOnHandler.ReplaceAllString(rawHTML, "$1")
	rawHTML = stripRemoteResourceAttrs(rawHTML)
	rawHTML = sanitizeStyleElements(rawHTML)
	return rawHTML
}

func sanitizeStyleElements(input string) string {
	return reStyleElement.ReplaceAllStringFunc(input, func(element string) string {
		openEnd := strings.IndexByte(element, '>')
		closeStart := strings.LastIndex(strings.ToLower(element), "</style")
		if openEnd < 0 || closeStart <= openEnd {
			return ""
		}
		return element[:openEnd+1] + sanitizeCSS(element[openEnd+1:closeStart]) + element[closeStart:]
	})
}

// sanitizeCSS first resolves CSS escapes and removes comments outside strings,
// because Chromium does both before interpreting URL-like functions. Regexing
// only the raw spelling lets u\72l(f\69le:/etc/passwd) and f/**/ile: variants
// evade an otherwise-correct URL check. All @import rules are removed: a static
// PDF has no attached stylesheet to import, and imports accept more URL spellings
// than url(). image-set/image are likewise unnecessary responsive fetch surfaces.
func sanitizeCSS(css string) string {
	css = decodeCSSEscapes(css)
	css = stripCSSComments(css)
	css = stripCSSImports(css)
	css = sanitizeCSSURLFunctions(css)
	css = reCSSImageSet.ReplaceAllString(css, "none")
	css = reCSSImageFunc.ReplaceAllString(css, "none")
	return css
}

func stripCSSComments(css string) string {
	var out strings.Builder
	out.Grow(len(css))
	var quote byte
	for i := 0; i < len(css); {
		if quote != 0 {
			out.WriteByte(css[i])
			if css[i] == '\\' && i+1 < len(css) {
				i++
				out.WriteByte(css[i])
			} else if css[i] == quote {
				quote = 0
			}
			i++
			continue
		}
		if css[i] == '\'' || css[i] == '"' {
			quote = css[i]
			out.WriteByte(css[i])
			i++
			continue
		}
		if css[i] == '/' && i+1 < len(css) && css[i+1] == '*' {
			end := strings.Index(css[i+2:], "*/")
			if end < 0 {
				break
			}
			i += end + 4
			continue
		}
		out.WriteByte(css[i])
		i++
	}
	return out.String()
}

func stripCSSImports(css string) string {
	var out strings.Builder
	out.Grow(len(css))
	for i := 0; i < len(css); {
		if !hasCSSKeywordAt(css, i, "@import") {
			out.WriteByte(css[i])
			i++
			continue
		}

		i += len("@import")
		var quote byte
		depth := 0
		for i < len(css) {
			c := css[i]
			if quote != 0 {
				if c == '\\' && i+1 < len(css) {
					i += 2
					continue
				}
				if c == quote {
					quote = 0
				}
				i++
				continue
			}
			switch c {
			case '\'', '"':
				quote = c
			case '(':
				depth++
			case ')':
				if depth > 0 {
					depth--
				}
			case ';':
				if depth == 0 {
					i++
					goto next
				}
			case '}':
				if depth == 0 {
					goto next
				}
			}
			i++
		}
	next:
	}
	return out.String()
}

func sanitizeCSSURLFunctions(css string) string {
	var out strings.Builder
	out.Grow(len(css))
	for i := 0; i < len(css); {
		if !hasCSSKeywordAt(css, i, "url") {
			out.WriteByte(css[i])
			i++
			continue
		}

		open := i + len("url")
		for open < len(css) && isCSSWhitespace(css[open]) {
			open++
		}
		if open >= len(css) || css[open] != '(' {
			out.WriteByte(css[i])
			i++
			continue
		}

		end, ok := cssFunctionEnd(css, open)
		if !ok {
			// Malformed URL functions have no legitimate static-render value;
			// consume the remainder rather than let Chromium repair it differently.
			out.WriteString("url(about:blank)")
			break
		}
		value := strings.TrimSpace(css[open+1 : end-1])
		if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if isUnsafeResourceURLValue(value) {
			out.WriteString("url(about:blank)")
		} else {
			out.WriteString(css[i:end])
		}
		i = end
	}
	return out.String()
}

func hasCSSKeywordAt(css string, offset int, keyword string) bool {
	if offset+len(keyword) > len(css) || !strings.EqualFold(css[offset:offset+len(keyword)], keyword) {
		return false
	}
	if offset > 0 && isCSSIdentifierByte(css[offset-1]) {
		return false
	}
	return offset+len(keyword) == len(css) || !isCSSIdentifierByte(css[offset+len(keyword)])
}

func isCSSIdentifierByte(b byte) bool {
	return b == '-' || b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// cssFunctionEnd returns the byte immediately after a URL function's closing
// parenthesis. Parentheses inside a quoted data URI do not end the function.
func cssFunctionEnd(css string, open int) (int, bool) {
	var quote byte
	for i := open + 1; i < len(css); i++ {
		c := css[i]
		if quote != 0 {
			if c == '\\' && i+1 < len(css) {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == ')' {
			return i + 1, true
		}
	}
	return len(css), false
}

func decodeCSSEscapes(css string) string {
	var out strings.Builder
	out.Grow(len(css))
	for i := 0; i < len(css); {
		if css[i] != '\\' || i+1 >= len(css) {
			out.WriteByte(css[i])
			i++
			continue
		}
		i++
		if css[i] == '\n' || css[i] == '\r' || css[i] == '\f' {
			i++ // escaped newline is a CSS line continuation
			continue
		}
		start := i
		for i < len(css) && i-start < 6 && isHexByte(css[i]) {
			i++
		}
		if i > start {
			code, err := strconv.ParseInt(css[start:i], 16, 32)
			if err == nil && code > 0 && code <= 0x10ffff {
				out.WriteRune(rune(code))
			}
			if i < len(css) && isCSSWhitespace(css[i]) {
				i++
			}
			continue
		}
		out.WriteByte(css[i])
		i++
	}
	return out.String()
}

func isHexByte(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

func isCSSWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

// stripRemoteResourceAttrs tokenizes the HTML and drops any resource attribute
// whose value (entity-decoded + normalized, the way Chromium reads it) resolves
// to a network or local-file fetch. Only tags that actually change are
// reserialized; every other token (text, <style> rawtext, comments, the doctype)
// is written back byte-for-byte, so the author's design is preserved.
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
		changed := false
		dropTag := false
		metaRefresh := false
		for {
			k, v, more := z.TagAttr()
			key := strings.ToLower(string(k))
			value := string(v)
			if key == "http-equiv" && strings.EqualFold(strings.TrimSpace(value), "refresh") {
				metaRefresh = true
			}
			if key == "srcset" || key == "imagesrcset" {
				// Responsive candidates add another comma-separated URL grammar.
				// The PDF has one fixed viewport and no author-supplied attachments,
				// so removing the attribute is both safer and deterministic.
				changed = true
			} else if resourceAttrs[key] && isUnsafeResourceURLValue(value) {
				changed = true
			} else {
				if cssResourceAttrs[key] {
					safe := sanitizeCSS(value)
					changed = changed || safe != value
					value = safe
				}
				kept = append(kept, attr{string(k), value})
			}
			if !more {
				break
			}
		}
		if strings.EqualFold(string(name), "meta") && metaRefresh {
			dropTag = true
		}
		if dropTag {
			continue
		}
		if !changed {
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

// isUnsafeResourceURLValue reports whether Chromium could resolve an
// author-controlled value outside the multipart render workspace. It handles
// file:/ (not just file://), root paths, Windows/backslash spellings, encoded
// slash/dot traversal, entity-decoded scheme text, and every network scheme.
// The small allowlist is intentional: these schemes cannot read a host resource,
// while ordinary non-traversing relative paths resolve only to attached assets.
func isUnsafeResourceURLValue(value string) bool {
	cleaned := cleanURLControls(value)
	if cleaned == "" || strings.HasPrefix(cleaned, "#") || strings.HasPrefix(cleaned, "?") {
		return false
	}
	if strings.HasPrefix(strings.ToLower(cleaned), "data:") {
		return false
	}

	for range 3 {
		decoded, err := url.PathUnescape(cleaned)
		if err != nil {
			return true
		}
		decoded = cleanURLControls(decoded)
		if decoded == cleaned {
			break
		}
		cleaned = decoded
	}
	cleaned = strings.ToLower(strings.ReplaceAll(cleaned, `\`, "/"))
	if cleaned == "" || strings.HasPrefix(cleaned, "#") || strings.HasPrefix(cleaned, "?") {
		return false
	}
	if strings.HasPrefix(cleaned, "/") {
		return true
	}

	if scheme, ok := resourceURLScheme(cleaned); ok {
		switch scheme {
		case "data", "mailto", "tel":
			return false
		case "about":
			return cleaned != "about:blank" && !strings.HasPrefix(cleaned, "about:blank#")
		default:
			return true
		}
	}

	pathPart := cleaned
	if cut := strings.IndexAny(pathPart, "?#"); cut >= 0 {
		pathPart = pathPart[:cut]
	}
	for _, segment := range strings.Split(pathPart, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

func cleanURLControls(value string) string {
	return strings.Map(func(r rune) rune {
		if r <= 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
}

func resourceURLScheme(value string) (string, bool) {
	colon := strings.IndexByte(value, ':')
	if colon <= 0 || value[0] < 'a' || value[0] > 'z' {
		return "", false
	}
	for i := 1; i < colon; i++ {
		c := value[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '+' && c != '-' && c != '.' {
			return "", false
		}
	}
	return value[:colon], true
}
