// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	pdfmodel "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	pdftypes "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/render"
)

// PDF-source finalization. A pdf-source document is the uploaded PDF itself;
// there is no block tree to render. We finalize by stamping each filled field
// value + each recipient's signature onto the original PDF at the
// page-percentage coordinates the sender placed in the field designer.
//
// Approach: for every page that carries fields, render a same-size HTML overlay
// (fields absolutely positioned by percentage) to a single-page PDF via the
// existing Gotenberg renderer, then overlay that page 1:1 onto the original
// page with pdfcpu. Stamping a full page at scale 1 / centered means the HTML
// top-left percentage coordinates map directly, with no PDF bottom-left
// coordinate math to get wrong.

// stampItem is one positioned overlay element (a field value or a signature),
// in page-percentage coordinates with pre-rendered inner HTML.
type stampItem struct {
	XPct, YPct, WPct, HPct float64
	HTML                   string
}

// buildPageOverlayHTML renders the overlay HTML for one page. The body fills
// the whole page; each item is absolutely positioned by percentage so it lands
// where the designer placed it once the page is stamped 1:1.
func buildPageOverlayHTML(items []stampItem) string {
	var sb strings.Builder
	sb.WriteString(`<!doctype html><html><head><meta charset="utf-8"><style>`)
	sb.WriteString(`html,body{margin:0;padding:0;height:100%;width:100%}`)
	sb.WriteString(`.f{position:absolute;box-sizing:border-box;display:flex;align-items:center;` +
		`font-family:Inter,system-ui,sans-serif;font-size:11px;color:#111;overflow:hidden;line-height:1.2}`)
	sb.WriteString(render.SignatureCSS())
	sb.WriteString(`</style></head><body>`)
	for _, it := range items {
		fmt.Fprintf(&sb,
			`<div class="f" style="left:%.3f%%;top:%.3f%%;width:%.3f%%;height:%.3f%%">%s</div>`,
			it.XPct, it.YPct, it.WPct, it.HPct, it.HTML)
	}
	sb.WriteString(`</body></html>`)
	return sb.String()
}

// stampOverlays overlays each single-page overlay PDF onto the matching page of
// the original. overlays is keyed by 1-based page number. Pages without an
// overlay are left untouched.
func stampOverlays(original []byte, overlays map[int][]byte) ([]byte, error) {
	conf := pdfmodel.NewDefaultConfiguration()
	conf.ValidationMode = pdfmodel.ValidationRelaxed
	conf.Unit = pdftypes.POINTS

	pages := make([]int, 0, len(overlays))
	for p := range overlays {
		pages = append(pages, p)
	}
	sort.Ints(pages)

	current := original
	for _, p := range pages {
		ov := overlays[p]
		if len(ov) == 0 {
			continue
		}
		// scale 1 absolute + centered + opaque = exact 1:1 page overlay.
		wm, err := pdfapi.PDFWatermarkForReadSeeker(
			bytes.NewReader(ov), 1, "scale:1 abs, pos:c, rot:0, op:1", true, false, pdftypes.POINTS)
		if err != nil {
			return nil, fmt.Errorf("build overlay watermark page %d: %w", p, err)
		}
		var buf bytes.Buffer
		if err := pdfapi.AddWatermarks(bytes.NewReader(current), &buf, []string{strconv.Itoa(p)}, wm, conf); err != nil {
			return nil, fmt.Errorf("stamp overlay page %d: %w", p, err)
		}
		current = buf.Bytes()
	}
	return current, nil
}

// mergePDFs concatenates PDFs in order into one (used to append the audit cert
// page to the stamped contract).
func mergePDFs(parts ...[]byte) ([]byte, error) {
	conf := pdfmodel.NewDefaultConfiguration()
	conf.ValidationMode = pdfmodel.ValidationRelaxed
	rss := make([]io.ReadSeeker, 0, len(parts))
	for _, p := range parts {
		rss = append(rss, bytes.NewReader(p))
	}
	var buf bytes.Buffer
	if err := pdfapi.MergeRaw(rss, &buf, false, conf); err != nil {
		return nil, fmt.Errorf("merge pdfs: %w", err)
	}
	return buf.Bytes(), nil
}

// loadSourcePDF fetches the uploaded PDF bytes backing a pdf-source document.
func (e *Engine) loadSourcePDF(ctx context.Context, doc *generated.Document) ([]byte, error) {
	if !doc.PdfStorageKey.Valid || doc.PdfStorageKey.String == "" {
		return nil, errors.New("pdf-source document has no stored pdf")
	}
	if len(doc.PdfSha256) != sha256.Size {
		return nil, errors.New("pdf-source document has no valid SHA-256 commitment")
	}
	var body []byte
	var err error
	if doc.PdfStorageVersionID.Valid && strings.TrimSpace(doc.PdfStorageVersionID.String) != "" {
		body, err = e.Storage.GetVerifiedVersion(ctx, doc.PdfStorageKey.String, doc.PdfStorageVersionID.String, doc.PdfSha256)
	} else if doc.EvidenceVersionPinsRequired {
		return nil, errors.New("pdf-source document is missing its required object VersionId")
	} else {
		body, _, err = e.Storage.ResolveVerifiedLegacy(ctx, doc.PdfStorageKey.String, doc.PdfSha256)
	}
	if err != nil {
		return nil, err
	}
	// Tripwire: the intake recorded pdf_sha256 of these bytes. Refuse to stamp +
	// ed25519-seal content that has drifted from the recorded digest (a
	// storage-layer source swap between intake and finalize). Zero cost, and it
	// also hardens the pre-existing template flow. Legacy/blocks docs with no
	// stored digest (len != 32) are unaffected.
	sum := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(sum[:], doc.PdfSha256) != 1 {
		return nil, errors.New("source pdf digest mismatch: stored bytes differ from the recorded intake hash")
	}
	return body, nil
}

// stampFieldsAndSignatures renders the field/signature overlays for every page
// of a pdf-source document and returns the stamped PDF (without the audit
// cert, which the caller appends). Pure of storage/DB beyond the queries it
// runs to read fields + signatures.
func (e *Engine) stampFieldsAndSignatures(ctx context.Context, doc *generated.Document, original []byte) ([]byte, error) {
	dimConf := pdfmodel.NewDefaultConfiguration()
	dimConf.ValidationMode = pdfmodel.ValidationRelaxed
	dims, err := pdfapi.PageDims(bytes.NewReader(original), dimConf)
	if err != nil {
		return nil, fmt.Errorf("read page dims: %w", err)
	}

	fields, err := e.Queries.ListFieldsByDocument(ctx, doc.ID)
	if err != nil {
		return nil, err
	}
	sigs, err := e.Queries.ListSignaturesByDocument(ctx, doc.ID)
	if err != nil {
		return nil, err
	}
	sigByRec := map[string]*generated.Signature{}
	for _, s := range sigs {
		if err := render.ValidateSignatureName(s.TypedName); err != nil {
			return nil, fmt.Errorf("stamp stored signature %s: %w", s.ID, err)
		}
		sigByRec[s.RecipientID.String()] = s
	}

	// Group overlay items by 1-based page number.
	byPage := map[int][]stampItem{}
	for _, f := range fields {
		inner, err := stampInnerHTML(f, sigByRec)
		if err != nil {
			return nil, err
		}
		if inner == "" {
			continue
		}
		page := int(f.Page)
		if err := validateStampTargetPage(f, len(dims)); err != nil {
			return nil, err
		}
		byPage[page] = append(byPage[page], stampItem{
			XPct: numericPct(f.XPct),
			YPct: numericPct(f.YPct),
			WPct: clampWidth(numericPct(f.WPct)),
			HPct: clampWidth(numericPct(f.HPct)),
			HTML: inner,
		})
	}
	if len(byPage) == 0 {
		// Nothing to stamp (a pdf with no placed fields): return as-is so the
		// signed PDF is still the authentic original.
		return original, nil
	}

	overlays := map[int][]byte{}
	for page, items := range byPage {
		dim := dims[page-1]
		html := buildPageOverlayHTML(items)
		overlayPDF, err := e.PDF.HTMLToPDF(ctx, html, render.PDFOptions{
			PaperWidth:  float32(dim.Width) / 72.0,
			PaperHeight: float32(dim.Height) / 72.0,
			Margins:     [4]float32{0, 0, 0, 0},
			WaitDelay:   "500ms",
		})
		if err != nil {
			return nil, fmt.Errorf("render overlay page %d: %w", page, err)
		}
		overlays[page] = overlayPDF
	}
	return stampOverlays(original, overlays)
}

// validateStampTargetPage is the terminal fail-closed counterpart to Send's
// PDF readiness check. A corrupt/legacy field or a future caller bypassing
// Send must never be silently omitted from the signed artifact.
func validateStampTargetPage(field *generated.DocumentField, pageCount int) error {
	if field == nil {
		return errors.New("stamp pdf: nil field")
	}
	if pageCount < 1 || field.Page < 1 || int(field.Page) > pageCount {
		return fmt.Errorf("stamp pdf: field %s targets page %d outside source page range 1..%d", field.ID, field.Page, pageCount)
	}
	return nil
}

// stampInnerHTML returns the HTML to place for a field: the recipient's
// signature span for signature fields, otherwise the (escaped) filled value.
// Returns "" when there is nothing to stamp (unsigned signature slot, empty
// value) so the page overlay stays minimal.
func stampInnerHTML(f *generated.DocumentField, sigByRec map[string]*generated.Signature) (string, error) {
	if f.Type == "signature" {
		if !f.RecipientID.Valid {
			return "", nil
		}
		sig, ok := sigByRec[uuid.UUID(f.RecipientID.Bytes).String()]
		if !ok {
			return "", nil
		}
		span, err := render.RenderSignatureSpan(sig.TypedName, sig.Font)
		if err != nil {
			return "", fmt.Errorf("stamp stored signature %s: %w", sig.ID, err)
		}
		return span, nil
	}
	if !f.Value.Valid || strings.TrimSpace(f.Value.String) == "" {
		return "", nil
	}
	val := f.Value.String
	if f.Type == "checkbox" {
		if isTruthy(val) {
			return "&#10003;", nil // check mark
		}
		return "", nil
	}
	return htmlEscape(val), nil
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on", "checked", "x":
		return true
	}
	return false
}

// numericPct converts a pgtype.Numeric percent (stored 0..100 with 4 frac
// digits) to a float64. Mirrors the handler's numericToFloat without crossing
// the package boundary.
func numericPct(n pgtype.Numeric) float64 {
	if !n.Valid || n.Int == nil {
		return 0
	}
	f, _ := new(big.Float).SetInt(n.Int).Float64()
	exp := int(n.Exp)
	for ; exp < 0; exp++ {
		f /= 10
	}
	for ; exp > 0; exp-- {
		f *= 10
	}
	return f
}

// clampWidth keeps a degenerate (zero) width/height field from collapsing to
// an invisible box; a placed field always gets at least a small footprint.
func clampWidth(v float64) float64 {
	if v <= 0 {
		return 12
	}
	return v
}
