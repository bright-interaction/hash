// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateNoUnpinnedStorageReferences(t *testing.T) {
	clean := &Tree{Version: SchemaVersion, Blocks: []Block{{ID: "raw", Type: TypeRawHTML, Text: `<p>Static terms</p>`}}}
	if err := ValidateNoUnpinnedStorageReferences(clean); err != nil {
		t.Fatalf("static raw HTML rejected: %v", err)
	}

	cases := []Block{
		{ID: "image", Type: TypeImage, Attrs: map[string]any{"storage_key": "org/o/image.png"}},
		{ID: "raw", Type: TypeRawHTML, Text: `<img src=/api/v1/storage/org/o/image.png>`},
		{ID: "raw-entity", Type: TypeRawHTML, Text: `<a href="&#47;api&#47;v1&#47;storage&#47;org/o/file">file</a>`},
		{ID: "raw-encoded", Type: TypeRawHTML, Text: `<img src="%252fapi%252fv1%252fstorage%252forg/o/image.png">`},
		{ID: "raw-dot-segments", Type: TypeRawHTML, Text: `<img src="/api/v1/x/../storage/org/o/image.png">`},
		{ID: "raw-encoded-dot-segments", Type: TypeRawHTML, Text: `<img src="%2fapi%2fv1%2fx%2f%2e%2e%2fstorage%2forg/o/image.png">`},
		{ID: "raw-malformed-percent", Type: TypeRawHTML, Text: `<img src="/api/v1/%zz/storage/org/o/image.png">`},
		{ID: "raw-srcset", Type: TypeRawHTML, Text: `<img srcset="/api/v1/storage/a 1x, /api/v1/storage/b 2x">`},
		{ID: "raw-srcset-dot-segments", Type: TypeRawHTML, Text: `<img srcset="/api/v1/x/../storage/a 1x, safe.png 2x">`},
	}
	for _, block := range cases {
		t.Run(block.ID, func(t *testing.T) {
			tree := &Tree{Version: SchemaVersion, Blocks: []Block{{
				ID: "outer", Type: TypeCallout, Content: []Block{{
					ID: "inner", Type: TypeConditional, Attrs: map[string]any{"expression": "show == true"}, Content: []Block{block},
				}},
			}}}
			if err := ValidateNoUnpinnedStorageReferences(tree); !errors.Is(err, ErrUnpinnedStorageReference) {
				t.Fatalf("nested storage reference error = %v", err)
			}
		})
	}
}

func TestValidateImmutableSigningEvidenceRejectsUnsupportedInteractiveFieldsRecursively(t *testing.T) {
	t.Parallel()
	clean := &Tree{Version: SchemaVersion, Blocks: []Block{
		{ID: "terms", Type: TypeParagraph, Text: "Fixed terms"},
		{ID: "signature", Type: TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}},
	}}
	if err := ValidateImmutableSigningEvidence(clean); err != nil {
		t.Fatalf("supported immutable tree rejected: %v", err)
	}

	for _, blockType := range []Type{TypeInitialField, TypeTextField, TypeDateField, TypeCheckbox} {
		blockType := blockType
		t.Run(string(blockType), func(t *testing.T) {
			t.Parallel()
			tree := &Tree{Version: SchemaVersion, Blocks: []Block{{
				ID: "outer", Type: TypeCallout, Content: []Block{{ID: "unsupported", Type: blockType}},
			}}}
			err := ValidateImmutableSigningEvidence(tree)
			if err == nil || !strings.Contains(err.Error(), string(blockType)) {
				t.Fatalf("nested unsupported block error = %v", err)
			}
		})
	}

	image := &Tree{Version: SchemaVersion, Blocks: []Block{{ID: "image", Type: TypeImage}}}
	if err := ValidateImmutableSigningEvidence(image); !errors.Is(err, ErrUnpinnedStorageReference) {
		t.Fatalf("image storage dependency error = %v", err)
	}
}
