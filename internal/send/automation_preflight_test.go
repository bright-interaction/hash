// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/recipients"
)

func TestValidateAutomationBlockRequest(t *testing.T) {
	t.Parallel()
	tree := blocks.Tree{Version: blocks.SchemaVersion, Blocks: []blocks.Block{
		{ID: "terms", Type: blocks.TypeParagraph, Text: "Agreement for {{customer.name}}"},
		{ID: "signature", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}},
	}}
	raw, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	validRecipient := []recipients.Values{{
		Role: "signer", Email: "ada@example.test", Name: "Ada", Locale: "en",
	}}
	if err := ValidateAutomationBlockRequest(raw, []byte(`{"customer.name":"Ada"}`), validRecipient); err != nil {
		t.Fatalf("valid automation request rejected: %v", err)
	}
	if err := ValidateAutomationBlockRequest(raw, []byte(`{}`), validRecipient); !errors.Is(err, ErrUnresolvedVariables) {
		t.Fatalf("unresolved variables error = %v", err)
	}
	wrongRole := []recipients.Values{{
		Role: "approver", Email: "ada@example.test", Name: "Ada", Locale: "en",
	}}
	if err := ValidateAutomationBlockRequest(raw, []byte(`{"customer.name":"Ada"}`), wrongRole); !errors.Is(err, ErrUnsupportedRecipientRole) {
		t.Fatalf("role mismatch error = %v", err)
	}

	unsupported := blocks.Tree{Version: blocks.SchemaVersion, Blocks: []blocks.Block{
		{ID: "image", Type: blocks.TypeImage, Attrs: map[string]any{"storage_key": "org/test/image.png"}},
		{ID: "signature", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}},
	}}
	unsupportedRaw, err := json.Marshal(unsupported)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAutomationBlockRequest(unsupportedRaw, []byte(`{}`), validRecipient); !errors.Is(err, ErrUnsupportedBlockEvidence) {
		t.Fatalf("unsupported evidence error = %v", err)
	}
}
