package dispatch

import "testing"

func TestMaskEmail(t *testing.T) {
	cases := map[string]string{
		"signer@example.com":     "s***@example.com",
		"a@b.co":                 "a***@b.co",
		"  jane.doe@firm.se  ":   "j***@firm.se",
		"":                       "[redacted]",
		"not-an-email":           "***",
		"trailing@":              "***",
	}
	for in, want := range cases {
		if got := MaskEmail(in); got != want {
			t.Errorf("MaskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScrubEmails(t *testing.T) {
	in := "550 5.1.1 <victim@acme.com>: recipient rejected; cc anna@acme.com"
	got := ScrubEmails(in)
	for _, leak := range []string{"victim@acme.com", "anna@acme.com"} {
		if contains(got, leak) {
			t.Errorf("ScrubEmails leaked %q: %s", leak, got)
		}
	}
	if !contains(got, "@acme.com") {
		t.Errorf("ScrubEmails should retain the domain for diagnostics: %s", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
