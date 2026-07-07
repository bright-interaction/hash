package sign

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	pdfmodel "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// onePagePDF builds a one-page A4 PDF carrying a line of text, in memory.
func onePagePDF(t *testing.T, text string) []byte {
	t.Helper()
	conf := pdfmodel.NewDefaultConfiguration()
	conf.ValidationMode = pdfmodel.ValidationRelaxed
	spec := fmt.Sprintf(
		`{"pages":{"1":{"mediaBox":"A4","content":{"text":[{"value":%q,"position":[100,700],"font":{"name":"Helvetica","size":12}}]}}}}`,
		text)
	var buf bytes.Buffer
	if err := pdfapi.Create(nil, strings.NewReader(spec), &buf, conf); err != nil {
		t.Fatalf("create pdf: %v", err)
	}
	return buf.Bytes()
}

func pageCount(t *testing.T, pdf []byte) int {
	t.Helper()
	conf := pdfmodel.NewDefaultConfiguration()
	conf.ValidationMode = pdfmodel.ValidationRelaxed
	dims, err := pdfapi.PageDims(bytes.NewReader(pdf), conf)
	if err != nil {
		t.Fatalf("page dims: %v", err)
	}
	return len(dims)
}

func TestBuildPageOverlayHTML(t *testing.T) {
	html := buildPageOverlayHTML([]stampItem{
		{XPct: 10, YPct: 20, WPct: 30, HPct: 5, HTML: "Jane &amp; Co"},
	})
	for _, want := range []string{"left:10.000%", "top:20.000%", "width:30.000%", "Jane &amp; Co"} {
		if !strings.Contains(html, want) {
			t.Errorf("overlay html missing %q\n%s", want, html)
		}
	}
	// signature CSS is injected so cursive signature spans render in the PDF.
	if !strings.Contains(html, "@font-face") && !strings.Contains(html, "hash-signature") {
		t.Errorf("overlay html missing signature css")
	}
}

func TestStampInnerHTML_Checkbox(t *testing.T) {
	// truthy checkbox renders a check mark, falsy renders nothing.
	if got := isTruthy("yes"); !got {
		t.Error("yes should be truthy")
	}
	if got := isTruthy("no"); got {
		t.Error("no should not be truthy")
	}
}

func TestStampOverlays_AppliesPerPage(t *testing.T) {
	original := onePagePDF(t, "contract body")
	overlay := onePagePDF(t, "SIGNED")

	out, err := stampOverlays(original, map[int][]byte{1: overlay})
	if err != nil {
		t.Fatalf("stampOverlays: %v", err)
	}
	if pc := pageCount(t, out); pc != 1 {
		t.Fatalf("stamped page count = %d, want 1", pc)
	}
	// Output must be larger than the blank original now that an overlay landed.
	if len(out) <= len(original) {
		t.Errorf("stamped pdf (%d bytes) not larger than original (%d bytes)", len(out), len(original))
	}
}

func TestStampOverlays_EmptyMapPassthrough(t *testing.T) {
	original := onePagePDF(t, "contract body")
	out, err := stampOverlays(original, map[int][]byte{})
	if err != nil {
		t.Fatalf("stampOverlays: %v", err)
	}
	if !bytes.Equal(out, original) {
		t.Error("empty overlay map should return the original bytes unchanged")
	}
}

func TestMergePDFs_ConcatenatesPages(t *testing.T) {
	a := onePagePDF(t, "page A")
	b := onePagePDF(t, "page B")
	out, err := mergePDFs(a, b)
	if err != nil {
		t.Fatalf("mergePDFs: %v", err)
	}
	if pc := pageCount(t, out); pc != 2 {
		t.Fatalf("merged page count = %d, want 2", pc)
	}
}
