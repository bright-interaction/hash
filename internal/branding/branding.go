// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package branding implements Phase 8.5: org-level theming with optional
// per-document overrides. The block tree stays brand-agnostic; themes
// apply purely at the rendering layer via CSS custom properties.
//
// Resolution order at render time:
//  1. document_branding_override row (if present, every non-null field wins)
//  2. org_branding row (the org's defaults)
//  3. system defaults (defined in DefaultBranding)
//
// This mirrors the atomicsite Branding -> theme map pattern so the same
// designers can move between products with the same mental model.
package branding

import (
	"context"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg" // register JPEG decoder
	_ "image/png"  // register PNG decoder
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// Branding is the resolved theme used by the renderer. All fields are
// non-empty after Resolve so the caller doesn't need nil checks.
type Branding struct {
	PrimaryHex     string `json:"primary_hex"`
	AccentHex      string `json:"accent_hex"`
	SurfaceHex     string `json:"surface_hex"`
	TextHex        string `json:"text_hex"`
	MutedHex       string `json:"muted_hex"`
	LogoURL        string `json:"logo_url"`
	LogoAlt        string `json:"logo_alt"`
	FontHeading    string `json:"font_heading"`
	FontBody       string `json:"font_body"`
	SignatureColor string `json:"signature_color"`
}

// DefaultBranding returns the system-default palette. Conservative,
// high-contrast, designed to look acceptable with no configuration.
func DefaultBranding() Branding {
	return Branding{
		PrimaryHex:     "#0F172A",
		AccentHex:      "#3B82F6",
		SurfaceHex:     "#FFFFFF",
		TextHex:        "#0F172A",
		MutedHex:       "#64748B",
		LogoURL:        "",
		LogoAlt:        "",
		FontHeading:    "Inter",
		FontBody:       "Inter",
		SignatureColor: "#0F172A",
	}
}

// Resolver loads org + per-doc branding from the DB and merges them.
type Resolver struct {
	Q *generated.Queries
}

func NewResolver(q *generated.Queries) *Resolver { return &Resolver{Q: q} }

// Resolve returns the branding to use for the supplied document. Pass
// uuid.Nil for docID to resolve org-only (e.g. for /settings/branding
// previews).
func (r *Resolver) Resolve(ctx context.Context, orgID, docID uuid.UUID) (Branding, error) {
	out := DefaultBranding()
	if r == nil || r.Q == nil {
		return out, nil
	}

	if orgID != uuid.Nil {
		if row, err := r.Q.GetOrgBranding(ctx, orgID); err == nil {
			out = applyOrgRow(out, row)
		}
		// pgx.ErrNoRows is fine; we fall back to defaults silently.
	}

	if docID != uuid.Nil {
		if row, err := r.Q.GetDocumentBrandingOverride(ctx, docID); err == nil {
			out = applyDocOverride(out, row)
		}
	}
	return out, nil
}

func applyOrgRow(b Branding, row *generated.OrgBranding) Branding {
	if row == nil {
		return b
	}
	if row.PrimaryHex != "" {
		b.PrimaryHex = row.PrimaryHex
	}
	if row.AccentHex != "" {
		b.AccentHex = row.AccentHex
	}
	if row.SurfaceHex != "" {
		b.SurfaceHex = row.SurfaceHex
	}
	if row.TextHex != "" {
		b.TextHex = row.TextHex
	}
	if row.MutedHex != "" {
		b.MutedHex = row.MutedHex
	}
	if row.LogoUrl != "" {
		b.LogoURL = row.LogoUrl
	}
	if row.LogoAlt != "" {
		b.LogoAlt = row.LogoAlt
	}
	if row.FontHeading != "" {
		b.FontHeading = safeFontFamily(row.FontHeading)
	}
	if row.FontBody != "" {
		b.FontBody = safeFontFamily(row.FontBody)
	}
	if row.SignatureColor != "" {
		b.SignatureColor = row.SignatureColor
	}
	return b
}

// safeFontFamily strips a stored font name to a safe CSS-identifier charset so a
// payload like `Inter;}*{display:none}` can never break out of the font-family rule
// and inject arbitrary CSS into the ed25519-signed audit cert or the final signed
// PDF (whose brandCSS wrapper is outside the signed payload). Render-time chokepoint:
// every downstream use (CSSVariables, quoteFontFamily, buildHTMLDocument) reads the
// sanitized value. Falls back to "Inter" when nothing safe remains.
func safeFontFamily(s string) string {
	var out []rune
	for _, r := range s {
		if r == ' ' || r == '_' || r == '-' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			out = append(out, r)
		}
		if len(out) >= 64 {
			break
		}
	}
	cleaned := strings.TrimSpace(string(out))
	if cleaned == "" {
		return "Inter"
	}
	return cleaned
}

func applyDocOverride(b Branding, row *generated.DocumentBrandingOverride) Branding {
	if row == nil {
		return b
	}
	if row.PrimaryHex.Valid && row.PrimaryHex.String != "" {
		b.PrimaryHex = row.PrimaryHex.String
	}
	if row.AccentHex.Valid && row.AccentHex.String != "" {
		b.AccentHex = row.AccentHex.String
	}
	if row.SurfaceHex.Valid && row.SurfaceHex.String != "" {
		b.SurfaceHex = row.SurfaceHex.String
	}
	if row.TextHex.Valid && row.TextHex.String != "" {
		b.TextHex = row.TextHex.String
	}
	if row.MutedHex.Valid && row.MutedHex.String != "" {
		b.MutedHex = row.MutedHex.String
	}
	if row.LogoUrl.Valid && row.LogoUrl.String != "" {
		b.LogoURL = row.LogoUrl.String
	}
	if row.LogoAlt.Valid && row.LogoAlt.String != "" {
		b.LogoAlt = row.LogoAlt.String
	}
	if row.FontHeading.Valid && row.FontHeading.String != "" {
		b.FontHeading = safeFontFamily(row.FontHeading.String)
	}
	if row.FontBody.Valid && row.FontBody.String != "" {
		b.FontBody = safeFontFamily(row.FontBody.String)
	}
	if row.SignatureColor.Valid && row.SignatureColor.String != "" {
		b.SignatureColor = row.SignatureColor.String
	}
	return b
}

// CSSVariables produces the <style>:root{...}</style> block the renderer
// prepends to every document. Output is safe to inline; values are
// validated by ValidateHex so we never inject untrusted strings into the
// stylesheet.
func (b Branding) CSSVariables() string {
	var sb strings.Builder
	sb.WriteString("<style>:root{")
	push := func(name, value string) {
		fmt.Fprintf(&sb, "%s:%s;", name, value)
	}
	push("--hash-primary", b.PrimaryHex)
	push("--hash-accent", b.AccentHex)
	push("--hash-surface", b.SurfaceHex)
	push("--hash-text", b.TextHex)
	push("--hash-muted", b.MutedHex)
	push("--hash-signature", b.SignatureColor)
	push("--hash-on-primary", ContrastTextOn(b.PrimaryHex))
	push("--hash-on-accent", ContrastTextOn(b.AccentHex))
	push("--hash-on-surface", ContrastTextOn(b.SurfaceHex))
	push("--hash-font-heading", quoteFontFamily(b.FontHeading))
	push("--hash-font-body", quoteFontFamily(b.FontBody))
	sb.WriteString("}</style>")
	return sb.String()
}

// ValidateHex returns true if s is a 3- or 6-char hex colour with an
// optional leading #. Used by the upsert handler to reject untrusted
// input before it reaches CSSVariables.
func ValidateHex(s string) bool {
	if s == "" {
		return false
	}
	return reHex.MatchString(s)
}

var reHex = regexp.MustCompile(`^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

// ValidateLogoURL guards the logo_url write boundary (MCP set_org_branding +
// REST branding upsert). The stored value is later rendered as an <img src> in
// the branded sign UI / emails, so an attacker-supplied javascript: or data:
// scheme would be a stored-XSS / scheme-abuse vector. We require an absolute
// http(s) URL with a host, or a same-origin relative path (the logo-upload
// endpoint returns "/branding/logo/<org>.png"-style paths). Empty is allowed:
// it clears the logo. Returns a generic error; the caller logs specifics.
func ValidateLogoURL(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	// Same-origin relative path (must be root-relative, not scheme-relative
	// "//host" which would resolve to an external origin).
	if strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return errors.New("logo_url is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("logo_url must be an http(s) URL")
	}
	if u.Host == "" {
		return errors.New("logo_url must include a host")
	}
	return nil
}

// NormaliseHex returns the canonical #RRGGBB form, expanding 3-char
// shorthand. Returns "" if the input fails ValidateHex.
func NormaliseHex(s string) string {
	if !ValidateHex(s) {
		return ""
	}
	body := strings.TrimPrefix(s, "#")
	if len(body) == 3 {
		body = string([]byte{body[0], body[0], body[1], body[1], body[2], body[2]})
	}
	return "#" + strings.ToUpper(body)
}

// ContrastTextOn returns "#FFFFFF" or "#111111" based on luminance, so a
// branded button's text stays readable regardless of the configured
// background. Matches the atomicsite contrastTextOn behaviour.
func ContrastTextOn(bgHex string) string {
	r, g, b, ok := parseHex(bgHex)
	if !ok {
		return "#111111"
	}
	// Relative luminance per WCAG.
	lum := 0.2126*float64(r)/255 + 0.7152*float64(g)/255 + 0.0722*float64(b)/255
	if lum > 0.55 {
		return "#111111"
	}
	return "#FFFFFF"
}

// quoteFontFamily wraps the value in quotes if it contains spaces so
// the CSS `font-family` rule parses correctly.
func quoteFontFamily(s string) string {
	if s == "" {
		return "Inter"
	}
	if strings.ContainsAny(s, " \t") {
		return `"` + strings.ReplaceAll(s, `"`, "") + `"`
	}
	return s
}

func parseHex(s string) (r, g, b int, ok bool) {
	if !ValidateHex(s) {
		return 0, 0, 0, false
	}
	body := strings.TrimPrefix(s, "#")
	if len(body) == 3 {
		body = string([]byte{body[0], body[0], body[1], body[1], body[2], body[2]})
	}
	rv, err := hexNibble(body[0:2])
	if err != nil {
		return 0, 0, 0, false
	}
	gv, err := hexNibble(body[2:4])
	if err != nil {
		return 0, 0, 0, false
	}
	bv, err := hexNibble(body[4:6])
	if err != nil {
		return 0, 0, 0, false
	}
	return rv, gv, bv, true
}

func hexNibble(s string) (int, error) {
	if len(s) != 2 {
		return 0, errors.New("nibble length")
	}
	n := 0
	for _, ch := range s {
		n <<= 4
		switch {
		case ch >= '0' && ch <= '9':
			n |= int(ch - '0')
		case ch >= 'a' && ch <= 'f':
			n |= int(ch-'a') + 10
		case ch >= 'A' && ch <= 'F':
			n |= int(ch-'A') + 10
		default:
			return 0, errors.New("nibble char")
		}
	}
	return n, nil
}

// ExtractPaletteFromLogo decodes a JPEG/PNG logo and returns a primary +
// accent suggestion using simple k-means quantization. Designed to be
// "good enough", the user can refine in the settings UI; this just
// gives them a starting point so first-time onboarding doesn't have to
// open Figma.
//
// Returns (primary, accent, ok=true) on success, or ok=false on decode
// failure. Caller falls back to the default palette in that case.
func ExtractPaletteFromLogo(r io.Reader) (primaryHex, accentHex string, ok bool) {
	img, _, err := image.Decode(r)
	if err != nil {
		return "", "", false
	}
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if width == 0 || height == 0 {
		return "", "", false
	}

	// Two-cluster k-means in RGB. Initialised with the corner pixel
	// (typically background) and the centre pixel (typically the mark).
	// Iterate 8 passes which is plenty for this resolution.
	type centroid struct{ r, g, b float64 }
	c := [2]centroid{}
	{
		ar, ag, ab, _ := img.At(bounds.Min.X, bounds.Min.Y).RGBA()
		c[0] = centroid{float64(ar >> 8), float64(ag >> 8), float64(ab >> 8)}
		cx := bounds.Min.X + width/2
		cy := bounds.Min.Y + height/2
		mr, mg, mb, _ := img.At(cx, cy).RGBA()
		c[1] = centroid{float64(mr >> 8), float64(mg >> 8), float64(mb >> 8)}
	}

	// Sample a max of ~10k pixels evenly to keep this fast on big logos.
	step := 1
	total := width * height
	if total > 10000 {
		step = total / 10000
		if step < 1 {
			step = 1
		}
	}

	for pass := 0; pass < 8; pass++ {
		var sum0, sum1 centroid
		n0, n1 := 0, 0
		idx := 0
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				idx++
				if idx%step != 0 {
					continue
				}
				rr, gg, bb, aa := img.At(x, y).RGBA()
				if aa>>8 < 200 { // skip transparent pixels
					continue
				}
				pr, pg, pb := float64(rr>>8), float64(gg>>8), float64(bb>>8)
				d0 := sq(pr-c[0].r) + sq(pg-c[0].g) + sq(pb-c[0].b)
				d1 := sq(pr-c[1].r) + sq(pg-c[1].g) + sq(pb-c[1].b)
				if d0 < d1 {
					sum0.r += pr
					sum0.g += pg
					sum0.b += pb
					n0++
				} else {
					sum1.r += pr
					sum1.g += pg
					sum1.b += pb
					n1++
				}
			}
		}
		if n0 > 0 {
			c[0] = centroid{sum0.r / float64(n0), sum0.g / float64(n0), sum0.b / float64(n0)}
		}
		if n1 > 0 {
			c[1] = centroid{sum1.r / float64(n1), sum1.g / float64(n1), sum1.b / float64(n1)}
		}
	}

	// The darker centroid becomes "primary", the more vibrant one
	// becomes "accent". Picking primary as dark gives readable text
	// against a white surface; accent gets to be the bright punch.
	lum0 := 0.299*c[0].r + 0.587*c[0].g + 0.114*c[0].b
	lum1 := 0.299*c[1].r + 0.587*c[1].g + 0.114*c[1].b
	primary, accent := c[0], c[1]
	if lum1 < lum0 {
		primary, accent = c[1], c[0]
	}
	return toHex(primary), toHex(accent), true
}

func sq(x float64) float64 { return x * x }

func toHex(c struct{ r, g, b float64 }) string {
	clip := func(v float64) int {
		if v < 0 {
			return 0
		}
		if v > 255 {
			return 255
		}
		return int(v + 0.5)
	}
	return fmt.Sprintf("#%02X%02X%02X", clip(c.r), clip(c.g), clip(c.b))
}
