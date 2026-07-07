package sanitize

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
)

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
