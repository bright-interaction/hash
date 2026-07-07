package blocks

import "testing"

func TestSanitizeRawHTML_StripsScriptAndHandlers(t *testing.T) {
	cases := []string{
		`<script>alert(1)</script>`,
		`<img src=x onerror="alert(1)">`,
		`<a href="javascript:alert(1)">x</a>`,
		`<iframe src="https://evil.example"></iframe>`,
		`<div onclick="steal()">hi</div>`,
	}
	for _, in := range cases {
		got := SanitizeRawHTML(in)
		for _, bad := range []string{"<script", "onerror", "onclick", "javascript:", "<iframe"} {
			if contains(got, bad) {
				t.Errorf("SanitizeRawHTML(%q) = %q still contains %q", in, got, bad)
			}
		}
	}
}

func TestSanitizeRawHTML_PreservesSignatureSpan(t *testing.T) {
	// The signing flow injects this through the same TypeRawHTML path; the
	// data-font attribute drives the cursive-font CSS selector and MUST survive.
	in := `<span class="hash-field--signed"><span class="hash-signature" data-font="Caveat">Anna Andersson</span></span>`
	got := SanitizeRawHTML(in)
	for _, want := range []string{`class="hash-signature"`, `data-font="Caveat"`, "Anna Andersson", `class="hash-field--signed"`} {
		if !contains(got, want) {
			t.Errorf("signature span lost %q after sanitize: %q", want, got)
		}
	}
}

func TestSanitizeRawHTML_KeepsSafeBodyMarkup(t *testing.T) {
	in := `<p>Hello <b>world</b></p><ul><li>a</li></ul>`
	got := SanitizeRawHTML(in)
	for _, want := range []string{"<p>", "<b>", "<ul>", "<li>"} {
		if !contains(got, want) {
			t.Errorf("safe markup %q dropped: %q", want, got)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
