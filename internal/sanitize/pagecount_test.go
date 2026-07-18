// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sanitize

import (
	"bytes"
	"fmt"
	"testing"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// buildTestPDF renders an n-page PDF via pdfcpu's create-from-JSON path
// (empty page objects render blank pages) so the page-count assertion runs
// against a real, pdfcpu-canonical document rather than a fragile literal.
func buildTestPDF(t *testing.T, pages int) []byte {
	t.Helper()
	var sb bytes.Buffer
	sb.WriteString(`{"pages":{`)
	for i := 1; i <= pages; i++ {
		if i > 1 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `"%d":{"content":{"text":[{"value":"page %d","anchor":"center","font":{"name":"Helvetica","size":12}}]}}`, i, i)
	}
	sb.WriteString(`}}`)
	var out bytes.Buffer
	if err := pdfapi.Create(nil, bytes.NewReader(sb.Bytes()), &out, model.NewDefaultConfiguration()); err != nil {
		t.Fatalf("build %d-page test pdf: %v", pages, err)
	}
	return out.Bytes()
}

func TestPageCount(t *testing.T) {
	if _, err := PageCount(nil); err == nil {
		t.Error("expected error for empty input")
	}
	if _, err := PageCount([]byte("not a pdf at all")); err == nil {
		t.Error("expected error for non-pdf input")
	}
	for _, want := range []int{1, 3} {
		pdf := buildTestPDF(t, want)
		got, err := PageCount(pdf)
		if err != nil {
			t.Fatalf("PageCount(%d-page pdf): %v", want, err)
		}
		if got != want {
			t.Errorf("PageCount = %d, want %d", got, want)
		}
	}
}
