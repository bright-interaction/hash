// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/storage"
)

type privateJSONFixture struct {
	Value string `json:"value"`
}

func writePrivateFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadExactPrivateJSONRequiresStablePrivateRegularFile(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.json")
	writePrivateFixture(t, valid, "{\"value\":\"expected\"}\n")
	var decoded privateJSONFixture
	if err := readExactPrivateJSON(valid, &decoded); err != nil || decoded.Value != "expected" {
		t.Fatalf("valid private JSON = %#v, %v", decoded, err)
	}

	tests := map[string]func() string{
		"symlink": func() string {
			path := filepath.Join(dir, "symlink.json")
			if err := os.Symlink(valid, path); err != nil {
				t.Fatal(err)
			}
			return path
		},
		"hardlink": func() string {
			path := filepath.Join(dir, "hardlink.json")
			if err := os.Link(valid, path); err != nil {
				t.Fatal(err)
			}
			return path
		},
		"permissive-mode": func() string {
			path := filepath.Join(dir, "permissive.json")
			writePrivateFixture(t, path, "{\"value\":\"expected\"}\n")
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
			return path
		},
		"unknown-field": func() string {
			path := filepath.Join(dir, "unknown.json")
			writePrivateFixture(t, path, "{\"value\":\"expected\",\"extra\":true}\n")
			return path
		},
		"trailing-json": func() string {
			path := filepath.Join(dir, "trailing.json")
			writePrivateFixture(t, path, "{\"value\":\"expected\"}\n{}\n")
			return path
		},
	}
	for name, makePath := range tests {
		t.Run(name, func(t *testing.T) {
			var got privateJSONFixture
			if err := readExactPrivateJSON(makePath(), &got); err == nil {
				t.Fatal("unsafe private JSON file was accepted")
			}
		})
	}
}

func testBootstrapEstateReceipt() storage.BootstrapEstateReceipt {
	digest := sha256.Sum256([]byte("fixed bootstrap marker"))
	return storage.BootstrapEstateReceipt{
		SchemaVersion:     storage.BootstrapEstateReceiptSchemaVersion,
		MarkerKey:         storage.BootstrapEstateMarkerKey,
		MarkerVersionID:   "provider-version-1",
		MarkerSHA256:      hex.EncodeToString(digest[:]),
		MarkerRetainUntil: "2035-01-02T03:04:05Z",
	}
}

func TestWriteBootstrapEstateReceiptIsCreateOnlyDurableAndPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "receipt")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "receipt.json")
	receipt := testBootstrapEstateReceipt()
	if err := writeBootstrapEstateReceiptCreateOnlyAt(path, receipt); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt mode = %v, want regular 0600", info.Mode())
	}
	var readback storage.BootstrapEstateReceipt
	if err := readExactPrivateJSON(path, &readback); err != nil || readback != receipt {
		t.Fatalf("receipt readback = %#v, %v", readback, err)
	}

	changed := receipt
	changed.MarkerVersionID = "provider-version-2"
	if err := writeBootstrapEstateReceiptCreateOnlyAt(path, changed); err == nil {
		t.Fatal("existing final receipt was overwritten")
	}
	readback = storage.BootstrapEstateReceipt{}
	if err := readExactPrivateJSON(path, &readback); err != nil || readback != receipt {
		t.Fatalf("failed overwrite changed receipt = %#v, %v", readback, err)
	}
}

func TestWriteBootstrapEstateReceiptRejectsPermissiveParent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "receipt")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeBootstrapEstateReceiptCreateOnlyAt(filepath.Join(dir, "receipt.json"), testBootstrapEstateReceipt()); err == nil {
		t.Fatal("permissive receipt directory was accepted")
	}
}

func TestCandidateCutoverScansImmutableBlockEvidenceInInventorySnapshot(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, want := range []string{
		"validateCandidateCutoverBlockEvidence(ctx, tx)",
		"blocks.ParseCanonicalTree(raw)",
		"blocks.ValidateImmutableSigningEvidence(tree)",
		"COALESCE(d.parent_envelope_id, d.id)",
		"si.retention_started_at IS NOT NULL",
		"FROM document_versions v",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("candidate-cutover block-evidence gate is missing %q", want)
		}
	}
	blockGate := strings.Index(source, "validateCandidateCutoverBlockEvidence(ctx, tx)")
	canonicalInventory := strings.Index(source, "tx.Query(ctx, string(query))")
	if blockGate < 0 || canonicalInventory < 0 || blockGate >= canonicalInventory {
		t.Fatal("block-evidence parser must run inside the repeatable-read transaction before canonical object inventory")
	}
}
