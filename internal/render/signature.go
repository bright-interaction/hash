// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// SupportedFonts is the curated calligraphy set the signer adoption modal
// offers. All five are OFL-licensed and self-hosted via go:embed; the bytes
// ship to Gotenberg as multipart attachments alongside index.html so the
// PDF render is hermetic (zero network, no third-party CDN).
var SupportedFonts = []string{
	"Caveat",
	"Dancing Script",
	"Great Vibes",
	"Sacramento",
	"Homemade Apple",
}

// IsValidFont reports whether the given font is one we offer signers.
func IsValidFont(font string) bool {
	for _, f := range SupportedFonts {
		if f == font {
			return true
		}
	}
	return false
}

//go:embed assets/Caveat.woff2
var fontCaveat []byte

//go:embed assets/DancingScript.woff2
var fontDancingScript []byte

//go:embed assets/GreatVibes.woff2
var fontGreatVibes []byte

//go:embed assets/Sacramento.woff2
var fontSacramento []byte

//go:embed assets/HomemadeApple.woff2
var fontHomemadeApple []byte

//go:embed assets/Inter.woff2
var fontInter []byte

//go:embed assets/Geist.woff2
var fontGeist []byte

// FontAsset names + bytes for a single woff2 face. Gotenberg attaches each
// one via the multipart form so Chromium can resolve relative url('./x.woff2')
// references in the inline CSS without ever hitting the network. Mime is
// optional; empty falls back to "font/woff2".
type FontAsset struct {
	Filename string
	Mime     string
	Bytes    []byte
}

// FontAssets returns every woff2 file the rendered HTML references. Call this
// when posting to Gotenberg so the signature + cert-page fonts resolve.
func FontAssets() []FontAsset {
	return []FontAsset{
		{Filename: "Caveat.woff2", Bytes: fontCaveat},
		{Filename: "DancingScript.woff2", Bytes: fontDancingScript},
		{Filename: "GreatVibes.woff2", Bytes: fontGreatVibes},
		{Filename: "Sacramento.woff2", Bytes: fontSacramento},
		{Filename: "HomemadeApple.woff2", Bytes: fontHomemadeApple},
		{Filename: "Inter.woff2", Bytes: fontInter},
		{Filename: "Geist.woff2", Bytes: fontGeist},
	}
}

// SignatureCSS returns a small stylesheet that loads the calligraphy fonts
// plus a class for rendering each signature. Concat this with the document
// body before sending to Gotenberg so signatures resolve. Font URLs are
// relative to index.html so Gotenberg + the embedded SPA both resolve them
// from the same multipart attachment set / self-hosted /fonts/ tree.
func SignatureCSS() string {
	return strings.TrimSpace(fmt.Sprintf(`
@font-face { font-family: 'Caveat';         font-style: normal; font-weight: 400; font-display: swap; src: url('./%s') format('woff2'); }
@font-face { font-family: 'Dancing Script'; font-style: normal; font-weight: 400; font-display: swap; src: url('./%s') format('woff2'); }
@font-face { font-family: 'Great Vibes';    font-style: normal; font-weight: 400; font-display: swap; src: url('./%s') format('woff2'); }
@font-face { font-family: 'Sacramento';     font-style: normal; font-weight: 400; font-display: swap; src: url('./%s') format('woff2'); }
@font-face { font-family: 'Homemade Apple'; font-style: normal; font-weight: 400; font-display: swap; src: url('./%s') format('woff2'); }
@font-face { font-family: 'Inter';          font-style: normal; font-weight: 300 700; font-display: swap; src: url('./%s') format('woff2'); }
@font-face { font-family: 'Geist';          font-style: normal; font-weight: 300 700; font-display: swap; src: url('./%s') format('woff2'); }

.hash-signature {
  display: inline-block;
  font-size: 36px;
  line-height: 1.1;
  vertical-align: baseline;
  color: #111;
}
.hash-signature[data-font="Caveat"]         { font-family: 'Caveat', cursive; }
.hash-signature[data-font="Dancing Script"] { font-family: 'Dancing Script', cursive; }
.hash-signature[data-font="Great Vibes"]    { font-family: 'Great Vibes', cursive; font-size: 42px; }
.hash-signature[data-font="Sacramento"]     { font-family: 'Sacramento', cursive; font-size: 40px; }
.hash-signature[data-font="Homemade Apple"] { font-family: 'Homemade Apple', cursive; font-size: 28px; }

.hash-field--signed {
  border-bottom: 1px solid #111;
  padding: 0.1em 0.3em;
  background: rgba(0, 0, 0, 0.02);
}

.hash-field--unsigned {
  border-bottom: 1px dashed #999;
  padding: 0.4em 0.6em;
  color: #999;
  font-style: italic;
  font-size: 0.95em;
}

.hash-cert-page {
  page-break-before: always;
  font-family: 'Inter', system-ui, sans-serif;
  font-size: 11px;
  color: #333;
}
.hash-cert-page h2 { font-family: 'Geist', 'Inter', sans-serif; font-weight: 200; font-size: 24px; }
.hash-cert-page table { border-collapse: collapse; width: 100%%; margin-top: 12px; }
.hash-cert-page th, .hash-cert-page td { padding: 6px 8px; border-bottom: 1px solid #eee; text-align: left; vertical-align: top; }
`,
		"Caveat.woff2",
		"DancingScript.woff2",
		"GreatVibes.woff2",
		"Sacramento.woff2",
		"HomemadeApple.woff2",
		"Inter.woff2",
		"Geist.woff2",
	))
}

const (
	// MaxSignatureNameRunes allows long international legal names while
	// bounding every persisted/audited/rendered copy of signer-controlled text.
	MaxSignatureNameRunes = 200
	// MaxSignatureNameBytes independently bounds storage and HTML expansion.
	// It accommodates MaxSignatureNameRunes four-byte Unicode code points.
	MaxSignatureNameBytes = MaxSignatureNameRunes * utf8.UTFMax
)

// ValidateSignatureName is shared by the ceremony and terminal render paths.
// Both limits matter: rune count is the human-facing ceiling, while byte count
// prevents combining/multi-byte input from bypassing the resource bound.
func ValidateSignatureName(typedName string) error {
	if !utf8.ValidString(typedName) {
		return errors.New("signature name must be valid UTF-8")
	}
	if strings.TrimSpace(typedName) == "" {
		return errors.New("signer must type a name")
	}
	if len(typedName) > MaxSignatureNameBytes {
		return fmt.Errorf("signature name must be at most %d bytes", MaxSignatureNameBytes)
	}
	if utf8.RuneCountInString(typedName) > MaxSignatureNameRunes {
		return fmt.Errorf("signature name must be at most %d characters", MaxSignatureNameRunes)
	}
	return nil
}

// RenderSignatureSpan returns the HTML span Hash stamps in place of a
// signature_field block once a signer adopts and signs. It validates again at
// the render boundary so corrupted legacy/database values fail closed instead
// of expanding terminal HTML/PDF evidence without bound.
func RenderSignatureSpan(typedName, font string) (string, error) {
	if err := ValidateSignatureName(typedName); err != nil {
		return "", err
	}
	if !IsValidFont(font) {
		font = "Caveat"
	}
	return fmt.Sprintf(`<span class="hash-signature" data-font="%s">%s</span>`,
		htmlAttrEscape(font), htmlContentEscape(typedName)), nil
}

func htmlAttrEscape(s string) string {
	r := strings.NewReplacer(`"`, "&quot;", "&", "&amp;")
	return r.Replace(s)
}

func htmlContentEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}
