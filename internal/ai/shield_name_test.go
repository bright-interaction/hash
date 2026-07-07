package ai

import (
	"context"
	"strings"
	"testing"
)

func TestShield_KnownNameRedactionRoundTrip(t *testing.T) {
	ls := newTestShield(t)
	in := "This NDA is between Acme AB and Jane Andersson. Reach Jane at jane@acme.se."
	out, h, err := ls.Tokenize(context.Background(), in, "Jane Andersson", "Acme AB")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "Jane Andersson") || strings.Contains(out, "Acme AB") {
		t.Errorf("party names not redacted: %q", out)
	}
	if !strings.Contains(out, "[shield:name:") {
		t.Errorf("expected a name token: %q", out)
	}
	// Pattern detection still runs alongside known-term redaction.
	if strings.Contains(out, "jane@acme.se") {
		t.Errorf("email not redacted: %q", out)
	}
	// The model echoes the tokens; Untokenize restores the originals.
	restored, err := ls.Untokenize(context.Background(), out, h)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(restored, "Jane Andersson") || !strings.Contains(restored, "Acme AB") {
		t.Errorf("untokenize did not restore names: %q", restored)
	}
}

func TestShield_NameRedactionCaseInsensitive(t *testing.T) {
	ls := newTestShield(t)
	out, _, _ := ls.Tokenize(context.Background(), "hello jane and JANE and Jane", "Jane")
	if strings.Contains(strings.ToLower(out), "jane") {
		t.Errorf("case-insensitive redaction failed: %q", out)
	}
}

func TestShield_NameRedactionWordBoundary(t *testing.T) {
	ls := newTestShield(t)
	// "Janet" must survive when the known term is "Jane".
	out, _, _ := ls.Tokenize(context.Background(), "Janet keeps her name", "Jane")
	if !strings.Contains(out, "Janet") {
		t.Errorf("over-redacted across word boundary: %q", out)
	}
}

func TestShield_NoopPassthroughWithTerms(t *testing.T) {
	out, _, err := NoopShield{}.Tokenize(context.Background(), "Jane Andersson", "Jane Andersson")
	if err != nil || out != "Jane Andersson" {
		t.Errorf("noop should pass through: %q %v", out, err)
	}
}
