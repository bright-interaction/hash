// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package templatepin

import (
	"bytes"
	"testing"
)

func TestCanonicalizeIsInvariantToJSONWhitespaceAndKeyOrder(t *testing.T) {
	t.Parallel()
	first, err := Canonicalize(
		[]byte(`{"version":1,"blocks":[{"id":"signature","type":"signature_field","attrs":{"required":true,"recipient_role":"signer"}},{"id":"body","type":"paragraph","text":"Hello {{customer.name}}"}]}`),
		[]byte(`{"customer.name":"Ada","company.name":"Example AB"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Canonicalize(
		[]byte(`{
			"blocks": [
				{"attrs":{"recipient_role":"signer","required":true},"type":"signature_field","id":"signature"},
				{"text":"Hello {{customer.name}}","id":"body","type":"paragraph"}
			],
			"version": 1
		}`),
		[]byte(`{ "company.name": "Example AB", "customer.name": "Ada" }`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.SHA256 != second.SHA256 {
		t.Fatalf("equivalent template JSON produced different commitments: %s != %s", first.SHA256Hex(), second.SHA256Hex())
	}
	if got, want := first.SHA256Hex(), "f96dfe15680cb99ba9ede01f1ef259c94a6bf9e88c9c0b0a5c17637820fabf71"; got != want {
		t.Fatalf("canonical digest changed: got %s, want %s", got, want)
	}
	if !bytes.Equal(first.BlocksJSON, second.BlocksJSON) || !bytes.Equal(first.VariablesJSON, second.VariablesJSON) {
		t.Fatalf("canonical content differs:\n%s\n%s\n%s\n%s", first.BlocksJSON, second.BlocksJSON, first.VariablesJSON, second.VariablesJSON)
	}
}

func TestCanonicalizeCommitsToBlocksAndDefaultVariables(t *testing.T) {
	t.Parallel()
	baseBlocks := []byte(`{"version":1,"blocks":[{"id":"body","type":"paragraph","text":"Hello {{customer.name}}"}]}`)
	base, err := Canonicalize(baseBlocks, []byte(`{"customer.name":"Ada"}`))
	if err != nil {
		t.Fatal(err)
	}
	changedBlocks, err := Canonicalize(
		[]byte(`{"version":1,"blocks":[{"id":"body","type":"paragraph","text":"Goodbye {{customer.name}}"}]}`),
		[]byte(`{"customer.name":"Ada"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	changedDefaults, err := Canonicalize(baseBlocks, []byte(`{"customer.name":"Grace"}`))
	if err != nil {
		t.Fatal(err)
	}
	if base.SHA256 == changedBlocks.SHA256 || base.SHA256 == changedDefaults.SHA256 {
		t.Fatal("content commitment did not cover both block content and canonical defaults")
	}
}

func TestCanonicalizeRejectsMutableTreeWithoutPersistedIDs(t *testing.T) {
	t.Parallel()
	if _, err := Canonicalize(
		[]byte(`{"version":1,"blocks":[{"type":"paragraph","text":"unstable"}]}`),
		[]byte(`{}`),
	); err == nil {
		t.Fatal("template commitment accepted a tree whose IDs would be generated nondeterministically")
	}
}
