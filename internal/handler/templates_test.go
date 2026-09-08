// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestTemplateResponseExposesCanonicalBlocksContentPin(t *testing.T) {
	t.Parallel()
	first, err := toTemplateResponse(&generated.Template{
		SourceKind:    "blocks",
		BlocksJson:    json.RawMessage(`{"version":1,"blocks":[{"id":"body","type":"paragraph","text":"Hello"}]}`),
		VariablesJson: json.RawMessage(`{"z":"last","a":"first"}`),
		Version:       4,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := toTemplateResponse(&generated.Template{
		SourceKind:    "blocks",
		BlocksJson:    json.RawMessage(`{ "blocks": [{"text":"Hello","type":"paragraph","id":"body"}], "version": 1 }`),
		VariablesJson: json.RawMessage(`{"a":"first","z":"last"}`),
		Version:       4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != 4 || first.ContentSHA256 != second.ContentSHA256 {
		t.Fatalf("template response pins = version %d, digests %q/%q", first.Version, first.ContentSHA256, second.ContentSHA256)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(first.ContentSHA256) {
		t.Fatalf("content_sha256 = %q, want 64 lowercase hex", first.ContentSHA256)
	}
}

func TestTemplateResponseDoesNotMislabelPDFDigestAsCanonicalBlocksContent(t *testing.T) {
	t.Parallel()
	response, err := toTemplateResponse(&generated.Template{
		SourceKind: "pdf", PdfSha256: []byte{0xaa}, Version: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.ContentSHA256 != "" || response.PDFSHA256 != "aa" {
		t.Fatalf("pdf response digests = content %q/pdf %q", response.ContentSHA256, response.PDFSHA256)
	}
}
