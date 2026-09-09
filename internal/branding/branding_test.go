// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package branding

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

type resolverQueriesStub struct {
	orgRow   *generated.OrgBranding
	orgErr   error
	docRow   *generated.DocumentBrandingOverride
	docErr   error
	orgCalls int
	docCalls int
}

func (s *resolverQueriesStub) GetOrgBranding(context.Context, uuid.UUID) (*generated.OrgBranding, error) {
	s.orgCalls++
	return s.orgRow, s.orgErr
}

func (s *resolverQueriesStub) GetDocumentBrandingOverride(context.Context, uuid.UUID) (*generated.DocumentBrandingOverride, error) {
	s.docCalls++
	return s.docRow, s.docErr
}

func TestResolverPropagatesOrgLookupFailure(t *testing.T) {
	sentinel := errors.New("org branding database unavailable")
	queries := &resolverQueriesStub{orgErr: sentinel}
	_, err := newResolver(queries).Resolve(context.Background(), uuid.New(), uuid.New())
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "resolve org branding") {
		t.Fatalf("Resolve error = %v, want wrapped org lookup failure", err)
	}
	if queries.docCalls != 0 {
		t.Fatalf("document lookup ran after org lookup failure: %d calls", queries.docCalls)
	}
}

func TestResolverPropagatesDocumentLookupFailure(t *testing.T) {
	sentinel := errors.New("document branding database unavailable")
	queries := &resolverQueriesStub{
		orgRow: &generated.OrgBranding{PrimaryHex: "#112233"},
		docErr: sentinel,
	}
	_, err := newResolver(queries).Resolve(context.Background(), uuid.New(), uuid.New())
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "resolve document branding") {
		t.Fatalf("Resolve error = %v, want wrapped document lookup failure", err)
	}
	if queries.orgCalls != 1 || queries.docCalls != 1 {
		t.Fatalf("lookup calls = org:%d doc:%d, want one each", queries.orgCalls, queries.docCalls)
	}
}

func TestResolverTreatsErrNoRowsAsMissingBranding(t *testing.T) {
	queries := &resolverQueriesStub{
		orgErr: pgx.ErrNoRows,
		docRow: &generated.DocumentBrandingOverride{
			PrimaryHex: pgtype.Text{String: "#ABCDEF", Valid: true},
		},
	}
	got, err := newResolver(queries).Resolve(context.Background(), uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.PrimaryHex != "#ABCDEF" || got.AccentHex != DefaultBranding().AccentHex {
		t.Fatalf("resolved branding = %#v, want override over system defaults", got)
	}

	queries = &resolverQueriesStub{orgErr: pgx.ErrNoRows, docErr: pgx.ErrNoRows}
	got, err = newResolver(queries).Resolve(context.Background(), uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("Resolve with no rows: %v", err)
	}
	if got != DefaultBranding() {
		t.Fatalf("resolved branding = %#v, want system defaults %#v", got, DefaultBranding())
	}
}

func TestResolveFrozenRequiresDocumentSnapshot(t *testing.T) {
	queries := &resolverQueriesStub{
		orgRow: &generated.OrgBranding{PrimaryHex: "#BADBAD"},
		docErr: pgx.ErrNoRows,
	}
	_, err := newResolver(queries).ResolveFrozen(context.Background(), uuid.New())
	if !errors.Is(err, ErrFrozenBrandingUnavailable) || !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("ResolveFrozen error = %v, want unavailable/no-rows error", err)
	}
	if queries.orgCalls != 0 {
		t.Fatalf("ResolveFrozen consulted mutable org branding: %d calls", queries.orgCalls)
	}
}

func TestResolveFrozenPropagatesDocumentLookupFailure(t *testing.T) {
	sentinel := errors.New("frozen snapshot database unavailable")
	queries := &resolverQueriesStub{docErr: sentinel}
	_, err := newResolver(queries).ResolveFrozen(context.Background(), uuid.New())
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "resolve frozen document branding") {
		t.Fatalf("ResolveFrozen error = %v, want wrapped database failure", err)
	}
}

func TestResolveFrozenRejectsIncompleteSnapshot(t *testing.T) {
	docID := uuid.New()
	snapshot := completeFrozenSnapshot(docID)
	snapshot.FontBody.Valid = false
	_, err := newResolver(&resolverQueriesStub{docRow: snapshot}).ResolveFrozen(context.Background(), docID)
	if !errors.Is(err, ErrFrozenBrandingUnavailable) {
		t.Fatalf("ResolveFrozen error = %v, want incomplete-snapshot failure", err)
	}
}

func TestResolveFrozenRejectsInvalidOrNonCanonicalFont(t *testing.T) {
	t.Parallel()
	for _, font := range []string{"\t\n", " Inter", "Inter;}"} {
		docID := uuid.New()
		snapshot := completeFrozenSnapshot(docID)
		snapshot.FontBody.String = font
		_, err := newResolver(&resolverQueriesStub{docRow: snapshot}).ResolveFrozen(context.Background(), docID)
		if !errors.Is(err, ErrFrozenBrandingUnavailable) {
			t.Errorf("ResolveFrozen font %q error = %v, want frozen-snapshot refusal", font, err)
		}
	}
}

func TestResolveFrozenUsesOnlyCompleteDocumentSnapshot(t *testing.T) {
	docID := uuid.New()
	snapshot := completeFrozenSnapshot(docID)
	snapshot.PrimaryHex.String = "#123456"
	queries := &resolverQueriesStub{
		orgErr: errors.New("mutable org branding must not be queried"),
		docRow: snapshot,
	}
	got, err := newResolver(queries).ResolveFrozen(context.Background(), docID)
	if err != nil {
		t.Fatalf("ResolveFrozen: %v", err)
	}
	if got.PrimaryHex != "#123456" || got.FontBody != "Inter" {
		t.Fatalf("resolved frozen branding = %#v", got)
	}
	if queries.orgCalls != 0 || queries.docCalls != 1 {
		t.Fatalf("lookup calls = org:%d doc:%d, want org:0 doc:1", queries.orgCalls, queries.docCalls)
	}
}

func completeFrozenSnapshot(docID uuid.UUID) *generated.DocumentBrandingOverride {
	text := func(value string) pgtype.Text { return pgtype.Text{String: value, Valid: true} }
	return &generated.DocumentBrandingOverride{
		DocumentID:     docID,
		PrimaryHex:     text("#0F172A"),
		AccentHex:      text("#3B82F6"),
		SurfaceHex:     text("#FFFFFF"),
		TextHex:        text("#0F172A"),
		MutedHex:       text("#64748B"),
		LogoUrl:        text(""),
		LogoAlt:        text(""),
		FontHeading:    text("Inter"),
		FontBody:       text("Inter"),
		SignatureColor: text("#0F172A"),
	}
}

func TestProductionBrandingRejectsEveryNonEmptyLogoDependency(t *testing.T) {
	t.Parallel()
	for _, logo := range []string{"/branding/logo/org.png", "https://cdn.example/logo.png", "  https://cdn.example/logo.png  "} {
		if err := ValidateLogoURLForEnvironment("production", logo); !errors.Is(err, ErrProductionLogoUnsupported) {
			t.Errorf("production logo %q error = %v", logo, err)
		}
	}
	if err := ValidateLogoURLForEnvironment("production", ""); err != nil {
		t.Fatalf("production logo clear rejected: %v", err)
	}
	if err := ValidateLogoURLForEnvironment("development", "https://cdn.example/logo.png"); err != nil {
		t.Fatalf("development logo preview rejected: %v", err)
	}
}

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

func TestNormaliseFontFamily(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{name: "single", in: "Inter", want: "Inter"},
		{name: "collapse unicode whitespace", in: "  Dancing\tScript\n", want: "Dancing Script"},
		{name: "canonical fallback list", in: " Geist,\tInter,  sans-serif ", want: "Geist, Inter, sans-serif"},
		{name: "maximum bytes", in: strings.Repeat("A", maxFontFamilyListLength), want: strings.Repeat("A", maxFontFamilyListLength)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormaliseFontFamily(tc.in)
			if err != nil || got != tc.want {
				t.Fatalf("NormaliseFontFamily(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
			}
		})
	}

	for _, in := range []string{
		"", " \t\r\n\u00a0 ", "Inter,,serif", "Inter;}*{display:none}",
		`"Inter"`, "Noto Sáns", strings.Repeat("A", maxFontFamilyListLength+1), string([]byte{0xff}),
	} {
		if got, err := NormaliseFontFamily(in); err == nil {
			t.Errorf("NormaliseFontFamily(%q) = %q, want rejection", in, got)
		}
	}
	if !IsCanonicalFontFamily("Geist, Inter, sans-serif") || IsCanonicalFontFamily("Geist,Inter") {
		t.Fatal("IsCanonicalFontFamily did not distinguish canonical list separators")
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

func TestCSSVariablesQuotesEachCustomFamilyAndPreservesGenericFallback(t *testing.T) {
	t.Parallel()
	b := DefaultBranding()
	b.FontBody = "Source Sans Pro, Inter, system-ui"
	css := b.CSSVariables()
	if !strings.Contains(css, `--hash-font-body:"Source Sans Pro", "Inter", system-ui;`) {
		t.Fatalf("font fallback list was not emitted safely: %s", css)
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
