package envelopes

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestManifestCanonicalSHAStable(t *testing.T) {
	m := Manifest{
		SchemaVersion: 1,
		EnvelopeID:    "11111111-1111-1111-1111-111111111111",
		EnvelopeTitle: "Acme Acquisition Package",
		Entries: []ManifestEntry{
			{ChildID: "aaa", Title: "Master Agreement", Position: 1, Status: "completed", FinalPDFSHA256: "deadbeef"},
			{ChildID: "bbb", Title: "DPA", Position: 2, Status: "completed", FinalPDFSHA256: "cafebabe"},
		},
	}
	m1 := m
	m2 := m
	m1.ManifestSHA = canonicalSHA(m1.canonicalBytes())
	m2.ManifestSHA = canonicalSHA(m2.canonicalBytes())
	if m1.ManifestSHA != m2.ManifestSHA {
		t.Fatalf("identical inputs produced different hashes: %s vs %s", m1.ManifestSHA, m2.ManifestSHA)
	}
	if _, err := hex.DecodeString(m1.ManifestSHA); err != nil {
		t.Fatalf("manifest hash should be hex: %v", err)
	}
}

func TestManifestCanonicalSHAChangesOnEdit(t *testing.T) {
	base := Manifest{
		EnvelopeID:    "11111111-1111-1111-1111-111111111111",
		EnvelopeTitle: "X",
		Entries: []ManifestEntry{
			{ChildID: "aaa", Title: "Master", Position: 1, FinalPDFSHA256: "deadbeef"},
		},
	}
	tampered := base
	tampered.Entries = append([]ManifestEntry{}, base.Entries...)
	tampered.Entries[0].FinalPDFSHA256 = "tampered"

	if canonicalSHA(base.canonicalBytes()) == canonicalSHA(tampered.canonicalBytes()) {
		t.Fatal("tampering with a child hash should change the manifest hash")
	}
}

func TestHTMLSectionEmpty(t *testing.T) {
	m := Manifest{}
	if got := m.HTMLSection(); got != "" {
		t.Fatalf("empty manifest should emit empty section, got %q", got)
	}
}

func TestHTMLSectionEmitsTableAndManifestHash(t *testing.T) {
	m := Manifest{
		EnvelopeID:    "abc",
		EnvelopeTitle: "Acme",
		Entries: []ManifestEntry{
			{ChildID: "c1", Title: "Master Agreement", Position: 1, Status: "completed", FinalPDFSHA256: "deadbeef"},
			{ChildID: "c2", Title: "DPA", Position: 2, Status: "in_progress", FinalPDFSHA256: ""},
		},
	}
	m.ManifestSHA = canonicalSHA(m.canonicalBytes())
	html := m.HTMLSection()
	for _, want := range []string{
		"Envelope manifest",
		"Master Agreement",
		"DPA",
		"deadbeef",
		"(not yet signed)",
		m.ManifestSHA,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTMLSection missing %q in:\n%s", want, html)
		}
	}
}

func TestHTMLSectionEscapesUntrustedTitle(t *testing.T) {
	m := Manifest{
		EnvelopeID:    "abc",
		EnvelopeTitle: "Acme",
		Entries: []ManifestEntry{
			{ChildID: "c1", Title: "<script>alert(1)</script>", Position: 1, Status: "completed", FinalPDFSHA256: "deadbeef"},
		},
	}
	html := m.HTMLSection()
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatalf("HTMLSection must escape angle brackets in titles: %s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatalf("expected escaped script tag, got %s", html)
	}
}
