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

func TestSanitizeRawHTML_BlocksRemoteResourceURLs(t *testing.T) {
	// SSRF: raw_html is rendered to PDF by Chromium; a remote <img src> makes it
	// dial an attacker-chosen internal host. Absolute + protocol-relative URLs
	// must be stripped; relative in-app paths must survive.
	blocked := map[string]string{
		`<img src="http://169.254.169.254/latest/meta-data/">`: "169.254.169.254",
		`<img src="http://minio:9000/hash/secret">`:            "minio:9000",
		`<img src="https://evil.example/x.png">`:               "evil.example",
		`<img src="//evil.example/x.png">`:                     "evil.example",
		`<a href="http://10.0.0.5/admin">x</a>`:                "10.0.0.5",
	}
	for in, bad := range blocked {
		if got := SanitizeRawHTML(in); contains(got, bad) {
			t.Errorf("SanitizeRawHTML(%q) = %q still contains remote target %q", in, got, bad)
		}
	}
	keep := `<img src="/api/v1/storage/org/doc/asset.png">`
	if got := SanitizeRawHTML(keep); !contains(got, "/api/v1/storage/org/doc/asset.png") {
		t.Errorf("relative in-app URL wrongly dropped: %q -> %q", keep, got)
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
