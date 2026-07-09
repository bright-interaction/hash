package sanitize

import (
	"bytes"
	"errors"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// PageCount reports the number of pages in a PDF. It runs pdfcpu in relaxed
// validation mode (matching cleanPDF) so a slightly-off-spec but readable PDF
// still yields its page count. Returns an error for empty / non-PDF /
// unreadable input so callers can fall back to a 0 placeholder rather than
// persist a wrong count.
func PageCount(raw []byte) (int, error) {
	if len(raw) == 0 {
		return 0, errors.New("sanitize: empty pdf")
	}
	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	n, err := pdfapi.PageCount(bytes.NewReader(raw), conf)
	if err != nil {
		return 0, err
	}
	return n, nil
}
