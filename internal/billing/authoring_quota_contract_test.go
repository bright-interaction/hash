// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package billing

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// Every production authoring surface that adds a row counted by billing must
// take the shared org lock and enforce from the same transaction after insert.
// The compliance seeder is deliberately absent: its two baseline documents and
// any recipients are explicitly excluded by the usage queries.
func TestCountedAuthoringCallsitesUseAtomicQuotaProtocol(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	files := []string{
		"internal/handler/documents.go",
		"internal/handler/documents_import.go",
		"internal/handler/recipients.go",
		"internal/mcp/tools_authoring.go",
		"internal/mcp/tools_envelopes.go",
	}
	for _, rel := range files {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		source := string(body)
		var inserts []int
		for _, marker := range []string{
			".CreateBlocksDocument(",
			".CreatePDFDocument(",
			".CreateRecipient(",
			"docintake.CreatePDFSourceDocument(",
		} {
			inserts = append(inserts, occurrenceIndexes(source, marker)...)
		}
		sort.Ints(inserts)
		locks := occurrenceIndexes(source, ".LockDocumentQuotaMutation(")
		enforcements := occurrenceIndexes(source, ".EnforceDocumentQuotaMutation(")
		if len(inserts) == 0 {
			t.Fatalf("%s no longer contains a recognized counted insert; update this contract intentionally", rel)
		}
		if len(locks) != len(inserts) || len(enforcements) != len(inserts) {
			t.Fatalf("%s counted inserts=%d locks=%d post-insert enforcements=%d", rel, len(inserts), len(locks), len(enforcements))
		}
		for i := range inserts {
			if !(locks[i] < inserts[i] && inserts[i] < enforcements[i]) {
				t.Fatalf("%s counted insert %d is not bracketed by its lock and post-insert enforcement", rel, i+1)
			}
		}
	}
}

func TestImportedPDFQuotaRollbackCompensatesStoredObject(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	tests := []struct {
		file    string
		cleanup string
	}{
		{file: "internal/handler/documents_import.go", cleanup: "deleteObjectDetached("},
		{file: "internal/mcp/tools_authoring.go", cleanup: "cleanupMCPImportedPDF("},
	}
	for _, test := range tests {
		body, err := os.ReadFile(filepath.Join(root, test.file))
		if err != nil {
			t.Fatalf("read %s: %v", test.file, err)
		}
		source := string(body)
		intake := strings.Index(source, "docintake.CreatePDFSourceDocument(")
		if intake < 0 {
			t.Fatalf("%s no longer contains the direct PDF intake", test.file)
		}
		tail := source[intake:]
		enforce := strings.Index(tail, ".EnforceDocumentQuotaMutation(")
		cleanup := strings.Index(tail, test.cleanup)
		if enforce < 0 || cleanup < 0 || cleanup < enforce {
			t.Fatalf("%s does not compensate the stored PDF after post-insert quota rejection", test.file)
		}
	}
}

func occurrenceIndexes(source, marker string) []int {
	var out []int
	for offset := 0; ; {
		i := strings.Index(source[offset:], marker)
		if i < 0 {
			return out
		}
		out = append(out, offset+i)
		offset += i + len(marker)
	}
}
