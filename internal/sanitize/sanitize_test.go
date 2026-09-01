// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sanitize

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
)

// buildObjectGraphPDF emits a small but structurally valid PDF with caller
// supplied catalog entries and indirect objects. Computing the xref offsets in
// the test keeps the fixtures readable while still exercising pdfcpu's real
// parser (including indirect, otherwise-unreferenced objects).
func buildObjectGraphPDF(t *testing.T, catalogExtra, pageExtra string, extraObjects ...string) []byte {
	t.Helper()
	objects := []string{
		fmt.Sprintf(`<< /Type /Catalog /Pages 2 0 R %s >>`, catalogExtra),
		`<< /Type /Pages /Kids [3 0 R] /Count 1 >>`,
		fmt.Sprintf(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R %s >>`, pageExtra),
		"<< /Length 0 >>\nstream\n\nendstream",
	}
	objects = append(objects, extraObjects...)

	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects)+1)
	for i, obj := range objects {
		offsets[i+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xrefOffset := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n", len(objects)+1)
	out.WriteString("0000000000 65535 f \n")
	for i := 1; i <= len(objects); i++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xrefOffset)
	return out.Bytes()
}

func TestClean_PassthroughForUnknownType(t *testing.T) {
	raw := []byte("hello")
	res, err := Clean("misc", "application/octet-stream", raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Report.UnsupportedT {
		t.Errorf("expected UnsupportedT=true for unknown type")
	}
	if res.Report.Method != "passthrough" {
		t.Errorf("expected passthrough method, got %q", res.Report.Method)
	}
	if !bytes.Equal(res.Bytes, raw) {
		t.Errorf("passthrough should not alter bytes")
	}
}

func TestClean_NilInputErrors(t *testing.T) {
	_, err := Clean("x", "application/pdf", nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestClean_PDFAllowsStaticDocument(t *testing.T) {
	res, err := Clean("template-pdf", "application/pdf", buildTestPDF(t, 1))
	if err != nil {
		t.Fatalf("clean static PDF: %v", err)
	}
	if !bytes.HasPrefix(res.Bytes, []byte("%PDF-")) {
		t.Fatalf("sanitized output is not a PDF: %q", res.Bytes[:min(8, len(res.Bytes))])
	}
}

func TestClean_PDFRejectsActiveObjectGraph(t *testing.T) {
	tests := []struct {
		name         string
		catalogExtra string
		extraObjects []string
		wantFeature  string
	}{
		{
			name:         "catalog open-action JavaScript",
			catalogExtra: "/OpenAction 5 0 R",
			extraObjects: []string{`<< /Type /Action /S /JavaScript /JS (app.alert\(1\)) >>`},
			wantFeature:  "/OpenAction",
		},
		{
			name:         "document additional action",
			catalogExtra: `/AA << /WC << /S /Launch /F (payload.exe) >> >>`,
			wantFeature:  "/AA",
		},
		{
			name:         "JavaScript name tree",
			catalogExtra: `/Names << /JavaScript << /Names [(startup) 5 0 R] >> >>`,
			extraObjects: []string{`<< /S /JavaScript /JS (this.print\(\)) >>`},
			wantFeature:  "/JavaScript",
		},
		{
			name:         "indirect launch action",
			catalogExtra: "/Outlines 5 0 R",
			extraObjects: []string{
				`<< /Type /Outlines /First 6 0 R /Last 6 0 R /Count 1 >>`,
				`<< /Title (run) /Parent 5 0 R /A 7 0 R >>`,
				`<< /Type /Action /S /Launch /F (payload.exe) >>`,
			},
			wantFeature: "action:/Launch",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildObjectGraphPDF(t, tc.catalogExtra, "", tc.extraObjects...)
			_, err := Clean("template-pdf", "application/pdf", raw)
			if !errors.Is(err, ErrActivePDFContent) {
				t.Fatalf("expected ErrActivePDFContent, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantFeature) {
				t.Fatalf("error %q does not identify %q", err, tc.wantFeature)
			}
		})
	}
}

func TestClean_PDFRemovesOrdinaryHyperlinkAnnotation(t *testing.T) {
	raw := buildObjectGraphPDF(t, "", "/Annots [5 0 R]",
		`<< /Type /Annot /Subtype /Link /Rect [10 10 100 30] /Border [0 0 0] /A << /S /URI /URI (https://example.com) >> >>`,
	)
	res, err := Clean("template-pdf", "application/pdf", raw)
	if err != nil {
		t.Fatalf("ordinary hyperlink should be removable, got %v", err)
	}
	active, err := activePDFFeatures(res.Bytes)
	if err != nil {
		t.Fatalf("inspect cleaned PDF: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("active hyperlink constructs survived annotation removal: %v", active)
	}
}

func TestClean_PNGRoundTripStripsMetadata(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			img.Set(x, y, color.RGBA{0x12, 0x34, 0x56, 0xFF})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode: %v", err)
	}
	res, err := Clean("logo", "image/png", buf.Bytes())
	if err != nil {
		t.Fatalf("clean: %v", err)
	}
	if res.Report.Method != "image-reencode" {
		t.Errorf("want image-reencode method, got %q", res.Report.Method)
	}
	wantStripped := map[string]bool{"exif": false, "gps": false, "icc_profile": false}
	for _, s := range res.Report.Stripped {
		if _, ok := wantStripped[s]; ok {
			wantStripped[s] = true
		}
	}
	for label, found := range wantStripped {
		if !found {
			t.Errorf("expected stripped report to mention %q", label)
		}
	}
	// The cleaned bytes decode as a PNG of the same dimensions.
	cleaned, _, err := image.Decode(bytes.NewReader(res.Bytes))
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if cleaned.Bounds().Dx() != 8 || cleaned.Bounds().Dy() != 8 {
		t.Fatalf("dimensions changed after sanitize: %v", cleaned.Bounds())
	}
}

func TestClean_JPEGRoundTripPreservesPixels(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			img.Set(x, y, color.RGBA{0xAA, 0xBB, 0xCC, 0xFF})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	res, err := Clean("logo", "image/jpeg", buf.Bytes())
	if err != nil {
		t.Fatalf("clean: %v", err)
	}
	if _, _, err := image.Decode(bytes.NewReader(res.Bytes)); err != nil {
		t.Fatalf("cleaned jpeg does not decode: %v", err)
	}
}

func TestClean_SVGStripsScriptsAndMetadata(t *testing.T) {
	in := `<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">
  <metadata id="x">
    <author>Tom Isgren</author>
    <gps>59.3,18.1</gps>
  </metadata>
  <script>alert('xss')</script>
  <!-- secret comment -->
  <rect width="10" height="10" fill="#3B82F6"/>
  <foreignObject><div>html-in-svg</div></foreignObject>
</svg>`
	res, err := Clean("logo", "image/svg+xml", []byte(in))
	if err != nil {
		t.Fatalf("clean: %v", err)
	}
	out := string(res.Bytes)
	for _, banned := range []string{"alert(", "<script", "<metadata", "Tom Isgren", "<foreignObject", "<!--"} {
		if strings.Contains(out, banned) {
			t.Errorf("SVG output still contains %q: %s", banned, out)
		}
	}
	if !strings.Contains(out, "<rect") {
		t.Errorf("benign <rect> should be preserved: %s", out)
	}
	if res.Report.Method != "svg-strip" {
		t.Errorf("want svg-strip method, got %q", res.Report.Method)
	}
}

func TestClean_SVGStripsGluedEventHandlers(t *testing.T) {
	// Glued attributes (no whitespace before the name) must be stripped too:
	// fill="red"onload=... and fill="x"xlink:href="javascript:...".
	in := `<svg xmlns="http://www.w3.org/2000/svg"><rect fill="red"onload="alert(1)"/><a fill="x"xlink:href="javascript:alert(2)">y</a></svg>`
	res, err := Clean("logo", "image/svg+xml", []byte(in))
	if err != nil {
		t.Fatalf("clean: %v", err)
	}
	out := string(res.Bytes)
	for _, banned := range []string{"onload", "javascript:"} {
		if strings.Contains(out, banned) {
			t.Errorf("glued attribute survived: %q still contains %q", out, banned)
		}
	}
	if !strings.Contains(out, `fill="red"`) {
		t.Errorf("legit attribute wrongly stripped: %s", out)
	}
}

func TestSyntheticTemplateReportShape(t *testing.T) {
	raw, err := SyntheticTemplateReport()
	if err != nil {
		t.Fatalf("synthetic report: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("expected non-empty report")
	}
	// MergeReports + a fresh empty input should produce a v1 report
	// with exactly one item.
	merged, err := MergeReports(raw, Report{Asset: "logo", Method: "image-reencode"})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !strings.Contains(string(merged), "template-pdf") || !strings.Contains(string(merged), "logo") {
		t.Errorf("merged report missing one of the items: %s", merged)
	}
}

func TestMergeReports_RecoversFromMalformedExisting(t *testing.T) {
	// A malformed existing payload must never break the write path.
	bad := []byte("not json")
	out, err := MergeReports(bad, Report{Asset: "logo", Method: "image-reencode"})
	if err != nil {
		t.Fatalf("merge from bad: %v", err)
	}
	if !strings.Contains(string(out), `"schema_version":1`) {
		t.Errorf("expected fresh v1 wrapper, got %s", out)
	}
}
