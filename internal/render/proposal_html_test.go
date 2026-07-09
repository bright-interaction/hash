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
			name:     "keeps relative path",
			in:       `<img src="/fonts/logo.png">`,
			mustKeep: []string{`src="/fonts/logo.png"`},
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
			name:     "drops iframe and meta refresh",
			in:       `<meta http-equiv="refresh" content="0;url=http://x"><iframe src="//x"></iframe><p>body</p>`,
			mustKeep: []string{"<p>body</p>"},
			mustDrop: []string{"<iframe", "http-equiv"},
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
