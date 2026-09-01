// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"strings"
	"testing"
)

func TestSanitizeForRender(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		mustKeep []string
		mustDrop []string
	}{
		{
			name:     "keeps style and inline css and layout",
			in:       `<style>.hero{color:#0891B2;display:grid}</style><div style="padding:40px" class="hero">Hi</div>`,
			mustKeep: []string{"<style>", "color:#0891B2", "display:grid", `style="padding:40px"`, `class="hero"`},
		},
		{
			name:     "keeps data uri image and font",
			in:       `<img src="data:image/png;base64,iVBORw0KGgo="><style>@font-face{src:url(data:font/woff2;base64,AAA)}</style>`,
			mustKeep: []string{"data:image/png;base64", "data:font/woff2;base64"},
		},
		{
			name:     "drops script block",
			in:       `<div>ok</div><script>fetch('http://169.254.169.254/')</script>`,
			mustKeep: []string{"<div>ok</div>"},
			mustDrop: []string{"<script", "169.254.169.254"},
		},
		{
			name:     "strips remote resource url",
			in:       `<img src="https://evil.example/x.png"><img src="//evil.example/y.png">`,
			mustDrop: []string{"evil.example"},
		},
		{
			// Regression: the old quote-anchored regex missed an UNQUOTED value.
			name:     "strips unquoted remote src (regex bypass)",
			in:       `<img src=http://metadata.evil.com/latest/meta-data/>`,
			mustDrop: []string{"metadata.evil.com", "meta-data"},
		},
		{
			// Regression: a quoted value with LEADING WHITESPACE that Chromium
			// trims and fetches, but the old regex failed to match.
			name:     "strips remote src with leading whitespace (regex bypass)",
			in:       `<img src=" http://169.254.169.254/latest/">`,
			mustDrop: []string{"169.254.169.254"},
		},
		{
			// Regression: an ENTITY-ENCODED scheme the parser decodes but a raw
			// regex never sees.
			name:     "strips entity-encoded remote scheme (regex bypass)",
			in:       `<img src="&#104;ttp://evil.example/x">`,
			mustDrop: []string{"evil.example"},
		},
		{
			name:     "strips protocol-relative with leading whitespace",
			in:       `<img src=" //evil.example/z">`,
			mustDrop: []string{"evil.example"},
		},
		{
			name:     "keeps unquoted relative src",
			in:       `<img src=fonts/logo.png alt=logo>`,
			mustKeep: []string{"logo.png"},
		},
		{
			name:     "keeps workspace-relative path and fragment",
			in:       `<img src="fonts/logo.png"><a href="#terms">terms</a><style>@font-face{src:url('./Caveat.woff2')}</style>`,
			mustKeep: []string{`src="fonts/logo.png"`, `href="#terms"`, `url('./Caveat.woff2')`},
		},
		{
			name: "strips local file resource attributes including svg xlink",
			in: `<img src="file:///etc/passwd"><video poster="file:/proc/self/environ"></video>` +
				`<svg><image href="f&#105;le:%2f%2f%2fetc/shadow"/>` +
				`<use xlink:href="file://localhost/etc/hosts"/></svg>`,
			mustDrop: []string{"file:", "/etc/passwd", "/proc/self/environ", "/etc/shadow", "/etc/hosts"},
		},
		{
			name: "strips absolute and parent-traversing resource paths",
			in: `<img src="/etc/passwd"><img src="&#47;proc/self/environ">` +
				`<img src="../../etc/shadow"><svg><use href="%2e%2e/%2e%2e/etc/hosts"/></svg>`,
			mustDrop: []string{"/etc/passwd", "/proc/self/environ", "../../etc/shadow", "%2e%2e", "/etc/hosts"},
		},
		{
			name:     "strips backslash and scheme-without-authority variants",
			in:       `<img src="..\\..\\etc\\passwd"><img src="http:169.254.169.254/latest"><img src="C:\\Windows\\win.ini">`,
			mustDrop: []string{"etc", "169.254.169.254", "Windows", "win.ini"},
		},
		{
			name:     "drops srcset rather than parsing alternate local candidates",
			in:       `<img src="data:image/png;base64,AAAA" srcset="safe.png 1x, file:///etc/passwd 2x">`,
			mustKeep: []string{"data:image/png;base64,AAAA"},
			mustDrop: []string{"srcset", "/etc/passwd"},
		},
		{
			name:     "strips on-handler",
			in:       `<div onload="steal()">x</div>`,
			mustKeep: []string{"<div", ">x</div>"},
			mustDrop: []string{"onload", "steal()"},
		},
		{
			name:     "rewrites remote css url, keeps data url",
			in:       `<style>.a{background:url(http://internal/secret)}.b{background:url(data:image/gif;base64,R0lGOD)}</style>`,
			mustKeep: []string{"url(about:blank)", "data:image/gif;base64,R0lGOD"},
			mustDrop: []string{"http://internal/secret"},
		},
		{
			name:     "drops remote css import",
			in:       `<style>@import url(https://evil.example/a.css);.a{color:red}</style>`,
			mustKeep: []string{"color:red"},
			mustDrop: []string{"evil.example"},
		},
		{
			name:     "blocks escaped css remote url",
			in:       `<style>.a{background:url(\68ttp://internal.minio/secret)}</style>`,
			mustKeep: []string{"url(about:blank)"},
			mustDrop: []string{"internal.minio", `\68ttp`},
		},
		{
			name: "blocks local css url absolute traversal encoded and escaped",
			in: `<style>` +
				`.a{background:url(file:/etc/passwd)}` +
				`.b{background:url('/proc/self/environ')}` +
				`.c{background:url(../../etc/shadow)}` +
				`.d{background:url(%2fetc%2fhosts)}` +
				`.e{background:url(\66 ile\3a /\2f etc/passwd)}` +
				`</style>`,
			mustKeep: []string{".a{background:url(about:blank)}", ".e{background:url(about:blank)}"},
			mustDrop: []string{"file:", "/etc/passwd", "/proc/self/environ", "../../etc/shadow", "%2fetc", `\66 ile`},
		},
		{
			name: "blocks local css url in inline and svg presentation attributes",
			in: `<div style="background:url('/etc/passwd')">x</div>` +
				`<svg><rect fill="url(file:///etc/shadow)" filter="url(%2fproc%2fself%2fenviron)"/>` +
				`<path marker-start="url(..\\..\\etc\\hosts)"/></svg>`,
			mustKeep: []string{`style="background:url(about:blank)"`, `fill="url(about:blank)"`, `filter="url(about:blank)"`, `marker-start="url(about:blank)"`},
			mustDrop: []string{"/etc/passwd", "file:", "%2fproc", "etc\\hosts"},
		},
		{
			name:     "drops every css import including local and data spellings",
			in:       `<style>@import "/etc/passwd";@import url(../../etc/shadow);@import url(data:text/css,.bad{});.safe{color:red}</style>`,
			mustKeep: []string{".safe{color:red}"},
			mustDrop: []string{"@import", "/etc/passwd", "../../etc/shadow", "data:text/css"},
		},
		{
			name:     "blocks css comment and escaped function obfuscation",
			in:       `<style>.a{background:u\72l(f/**/ile:/etc/passwd)}</style>`,
			mustKeep: []string{"url(about:blank)"},
			mustDrop: []string{"file:", "/etc/passwd", `u\72l`, "/**/"},
		},
		{
			name:     "blocks image set remote url",
			in:       `<style>.a{background-image:image-set("https://internal.minio/a" 1x)}</style><div style="background:-webkit-image-set('//internal.minio/b' 1x)">x</div>`,
			mustKeep: []string{"background-image:none", `style="background:none"`},
			mustDrop: []string{"internal.minio", "image-set("},
		},
		{
			name:     "blocks image function remote string",
			in:       `<style>.a{background:image("https://internal.minio/a")}</style>`,
			mustKeep: []string{"background:none"},
			mustDrop: []string{"internal.minio", `image("`},
		},
		{
			name:     "drops iframe and meta refresh",
			in:       `<meta http-equiv="refresh" content="0;url=http://x"><iframe src="//x"></iframe><p>body</p>`,
			mustKeep: []string{"<p>body</p>"},
			mustDrop: []string{"<iframe", "http-equiv"},
		},
		{
			name:     "drops entity encoded meta refresh and svg animation setters",
			in:       `<meta http-equiv="ref&#114;esh" content="0;url=file:///etc/passwd"><svg><set attributeName="href" to="file:///etc/shadow"/><animate attributeName="href" values="file:///etc/hosts"/></svg><p>body</p>`,
			mustKeep: []string{"<p>body</p>"},
			mustDrop: []string{"http-equiv", "file:", "<set", "<animate"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeForRender(tc.in)
			for _, k := range tc.mustKeep {
				if !strings.Contains(got, k) {
					t.Errorf("expected output to keep %q\n got: %s", k, got)
				}
			}
			for _, d := range tc.mustDrop {
				if strings.Contains(got, d) {
					t.Errorf("expected output to drop %q\n got: %s", d, got)
				}
			}
		})
	}
}

func TestUnsafeResourceURLValue(t *testing.T) {
	tests := []struct {
		value  string
		unsafe bool
	}{
		{value: "./Caveat.woff2"},
		{value: "fonts/logo.png"},
		{value: "data:image/png;base64,AAAA"},
		{value: "#signature"},
		{value: "mailto:signer@example.com"},
		{value: "tel:+461234567"},
		{value: "about:blank"},
		{value: "file:///etc/passwd", unsafe: true},
		{value: "file:/etc/passwd", unsafe: true},
		{value: "/etc/passwd", unsafe: true},
		{value: `..\..\etc\passwd`, unsafe: true},
		{value: "%252e%252e%252fetc%252fpasswd", unsafe: true},
		{value: "https://169.254.169.254/latest", unsafe: true},
		{value: "http:169.254.169.254/latest", unsafe: true},
		{value: "web+local:/etc/passwd", unsafe: true},
		{value: "h1:/etc/passwd", unsafe: true},
		{value: "custom-scheme.2:/etc/passwd", unsafe: true},
		{value: "//internal.minio/hash", unsafe: true},
		{value: "%zz", unsafe: true},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			if got := isUnsafeResourceURLValue(test.value); got != test.unsafe {
				t.Fatalf("isUnsafeResourceURLValue(%q) = %t, want %t", test.value, got, test.unsafe)
			}
		})
	}
}
