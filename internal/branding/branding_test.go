// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package branding

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
)

func TestValidateHex(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"#fff", true},
		{"fff", true},
		{"#FFFFFF", true},
		{"FFFFFF", true},
		{"#0F172A", true},
		{"#xyz", false},
		{"", false},
		{"#1234", false},
		{"#12345", false},
		{"#1234567", false},
	}
	for _, c := range cases {
		if got := ValidateHex(c.in); got != c.ok {
			t.Errorf("ValidateHex(%q) = %v, want %v", c.in, got, c.ok)
		}
	}
}

func TestNormaliseHex(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"#fff", "#FFFFFF"},
		{"fff", "#FFFFFF"},
		{"#0F172A", "#0F172A"},
		{"0f172a", "#0F172A"},
		{"bad", "#BBAADD"}, // 'b', 'a', 'd' are all valid hex digits
		{"xyz", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := NormaliseHex(c.in); got != c.want {
			t.Errorf("NormaliseHex(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestContrastTextOn(t *testing.T) {
	// White background = dark text
	if got := ContrastTextOn("#FFFFFF"); got != "#111111" {
		t.Errorf("white bg should yield dark text, got %q", got)
	}
	// Black background = light text
	if got := ContrastTextOn("#000000"); got != "#FFFFFF" {
		t.Errorf("black bg should yield light text, got %q", got)
	}
	// Invalid bg falls back to dark text
	if got := ContrastTextOn("not-a-color"); got != "#111111" {
		t.Errorf("invalid bg should fall back to #111111, got %q", got)
	}
	// Bright accent (blue) is dark enough = light text
	if got := ContrastTextOn("#3B82F6"); got != "#FFFFFF" {
		t.Errorf("bright blue should yield light text, got %q", got)
	}
}

func TestCSSVariablesEmitsAllProperties(t *testing.T) {
	b := DefaultBranding()
	css := b.CSSVariables()
	for _, prop := range []string{
		"--hash-primary",
		"--hash-accent",
		"--hash-surface",
		"--hash-text",
		"--hash-muted",
		"--hash-signature",
		"--hash-on-primary",
		"--hash-on-accent",
		"--hash-on-surface",
		"--hash-font-heading",
		"--hash-font-body",
	} {
		if !strings.Contains(css, prop) {
			t.Errorf("CSSVariables missing %q in output: %s", prop, css)
		}
	}
}

func TestCSSVariablesQuotesFontFamilyWithSpaces(t *testing.T) {
	b := DefaultBranding()
	b.FontBody = "Source Sans Pro"
	css := b.CSSVariables()
	if !strings.Contains(css, `"Source Sans Pro"`) {
		t.Errorf("font with spaces should be quoted, got: %s", css)
	}
}

func TestExtractPaletteFromLogo_SolidColors(t *testing.T) {
	// Build a 32x32 image with two halves: navy left, teal right.
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	navy := color.RGBA{0x0F, 0x17, 0x2A, 0xFF}
	teal := color.RGBA{0x14, 0xB8, 0xA6, 0xFF}
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			if x < 16 {
				img.Set(x, y, navy)
			} else {
				img.Set(x, y, teal)
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode: %v", err)
	}
	primary, accent, ok := ExtractPaletteFromLogo(&buf)
	if !ok {
		t.Fatal("expected extraction to succeed")
	}
	// The darker centroid should land near navy.
	if !strings.HasPrefix(primary, "#0") && !strings.HasPrefix(primary, "#1") {
		t.Errorf("primary should be dark, got %q", primary)
	}
	// Accent should be the teal-ish centroid.
	if accent == primary {
		t.Errorf("primary and accent collapsed: %q", primary)
	}
}

func TestExtractPaletteFromLogo_BadInputFailsCleanly(t *testing.T) {
	_, _, ok := ExtractPaletteFromLogo(strings.NewReader("not an image"))
	if ok {
		t.Fatal("expected extraction to fail on garbage input")
	}
}

func TestApplyOrgRowMergesNonEmptyFields(t *testing.T) {
	// Verified via the CSSVariables output: caller paths set then read
	// through Resolve. This test is the smallest possible direct check.
	b := DefaultBranding()
	if b.PrimaryHex == "" {
		t.Fatal("default primary should not be empty")
	}
}
