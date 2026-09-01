// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The first-view transition is intentionally idempotent: repeat page loads do
// not append new document.viewed evidence. Keep the public evidence description
// aligned with that model so recipients are not promised telemetry we do not
// collect.
func TestPublicEIDASPageDescribesFirstViewEvidence(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	body, err := os.ReadFile(filepath.Join(root, "frontend", "src", "routes", "legal", "eidas", "+page.svelte"))
	if err != nil {
		t.Fatalf("read public eIDAS page: %v", err)
	}
	page := strings.ToLower(string(body))
	if !strings.Contains(page, "first document view") {
		t.Fatal("public eIDAS page must describe the first-view evidence boundary")
	}
	if strings.Contains(page, "every view") {
		t.Fatal("public eIDAS page claims repeat views are recorded")
	}
}
